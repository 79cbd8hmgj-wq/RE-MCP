import assert from "node:assert/strict";
import net from "node:net";
import test from "node:test";

import { DebugController } from "../src/services/debug-controller.js";
import { encodeRspPacket, parseRspPacket } from "../src/services/gdb-rsp.js";
import { GdbSession } from "../src/services/gdb-session.js";
import type { Arm9ExecutableRange } from "../src/services/nds-arm9.js";

const ARM9_RANGE: Arm9ExecutableRange = {
  start: 0x02000000,
  end: 0x02001000,
  size: 0x1000,
  source: "arm9-header",
  label: "ARM9 main",
};

function littleEndianU32(value: number): string {
  const buffer = Buffer.alloc(4);
  buffer.writeUInt32LE(value >>> 0, 0);
  return buffer.toString("hex");
}

function registerPacket(options: {
  readonly pc: number;
  readonly sp?: number;
  readonly cpsr?: number;
}): string {
  const registers = Array.from({ length: 16 }, (_, index) => 0x10000000 + index);
  registers[13] = options.sp ?? 0x02000800;
  registers[15] = options.pc;
  return [
    ...registers.map(littleEndianU32),
    "0".repeat(8 * 24),
    "0".repeat(8),
    littleEndianU32(options.cpsr ?? 0x60000013),
  ].join("");
}

interface ScriptedReply {
  readonly command: string;
  readonly reply: string | null;
}

async function listen(server: net.Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("Expected TCP address");
  return address.port;
}

async function close(server: net.Server): Promise<void> {
  await new Promise<void>((resolve) => server.close(() => resolve()));
}

function scriptedRspServer(script: readonly ScriptedReply[], received: string[]): net.Server {
  const remaining = [...script];
  return net.createServer((socket) => {
    let buffer = "";

    const respond = (command: string): void => {
      received.push(command);
      const expected = remaining.shift();
      if (expected === undefined) throw new Error(`Unexpected GDB command: ${command}`);
      assert.equal(command, expected.command);
      if (command !== "INTERRUPT") socket.write("+", "ascii");
      if (expected.reply !== null) socket.write(encodeRspPacket(expected.reply), "ascii");
    };

    socket.on("data", (chunk) => {
      if (chunk.includes(0x03)) {
        respond("INTERRUPT");
        return;
      }
      buffer += chunk.toString("ascii");
      for (;;) {
        const parsed = parseRspPacket(buffer);
        if (parsed === null) return;
        buffer = buffer.slice(parsed.consumed);
        respond(parsed.payload);
      }
    });
  });
}

function controllerFor(port: number): DebugController {
  return new DebugController(() =>
    new GdbSession({
      host: "127.0.0.1",
      port,
      maxReplyBytes: 32_768,
      connectTimeoutMs: 1000,
    }),
  );
}

test("matches a stopped PC to a breakpoint and increments its hit count", async () => {
  const received: string[] = [];
  const server = scriptedRspServer(
    [
      { command: "Z0,2000000,4", reply: "OK" },
      { command: "c", reply: "S05" },
      { command: "g", reply: registerPacket({ pc: 0x02000000 }) },
    ],
    received,
  );
  const port = await listen(server);
  const controller = controllerFor(port);

  try {
    controller.initialize("session", ARM9_RANGE);
    const breakpoint = await controller.addBreakpoint({
      address: 0x02000000,
      mode: "arm",
      timeoutMs: 1000,
    });
    const result = await controller.continueExecution({
      timeoutMs: 1000,
      captureContext: false,
      expectedBreakpointId: breakpoint.id,
    });

    assert.equal(result.kind, "stop");
    if (result.kind !== "stop") throw new Error("Expected stop result");
    assert.equal(result.matchedBreakpoint?.id, breakpoint.id);
    assert.equal(result.matchedBreakpoint?.hitCount, 1);
    assert.equal(result.expectedBreakpointMatched, true);
    assert.equal(result.emulatorRunning, true);
    assert.match(result.stoppedAt, /^\d{4}-\d{2}-\d{2}T/);
    assert.equal(result.context, undefined);
    assert.deepEqual(received, ["Z0,2000000,4", "c", "g"]);
  } finally {
    await controller.reset("test cleanup");
    await close(server);
  }
});

test("records stopped execution mode for later auto breakpoint resolution", async () => {
  const received: string[] = [];
  const server = scriptedRspServer(
    [
      { command: "c", reply: "S05" },
      { command: "g", reply: registerPacket({ pc: 0x02000004, cpsr: 0x60000013 }) },
      { command: "Z0,2000004,4", reply: "OK" },
    ],
    received,
  );
  const port = await listen(server);
  const controller = controllerFor(port);

  try {
    controller.initialize("session", ARM9_RANGE);
    await controller.continueExecution({ timeoutMs: 1000, captureContext: false });
    const breakpoint = await controller.addBreakpoint({
      address: 0x02000004,
      mode: "auto",
      timeoutMs: 1000,
    });
    assert.equal(breakpoint.resolvedMode, "arm");
    assert.deepEqual(received, ["c", "g", "Z0,2000004,4"]);
  } finally {
    await controller.reset("test cleanup");
    await close(server);
  }
});

test("returns an unexpected stop instead of discarding it", async () => {
  const received: string[] = [];
  const server = scriptedRspServer(
    [
      { command: "Z0,2000000,4", reply: "OK" },
      { command: "c", reply: "S05" },
      { command: "g", reply: registerPacket({ pc: 0x02000008 }) },
    ],
    received,
  );
  const port = await listen(server);
  const controller = controllerFor(port);

  try {
    controller.initialize("session", ARM9_RANGE);
    const expected = await controller.addBreakpoint({
      address: 0x02000000,
      mode: "arm",
      timeoutMs: 1000,
    });
    const result = await controller.continueExecution({
      timeoutMs: 1000,
      captureContext: false,
      expectedBreakpointId: expected.id,
    });
    assert.equal(result.kind, "stop");
    if (result.kind !== "stop") throw new Error("Expected stop result");
    assert.equal(result.stop.raw, "S05");
    assert.equal(result.matchedBreakpoint, undefined);
    assert.equal(result.expectedBreakpointMatched, false);
  } finally {
    await controller.reset("test cleanup");
    await close(server);
  }
});

test("continue attaches structured context when requested", async () => {
  const received: string[] = [];
  const server = scriptedRspServer(
    [
      { command: "c", reply: "S05" },
      { command: "g", reply: registerPacket({ pc: 0x02000200, sp: 0x02000800 }) },
      { command: "m20001e0,40", reply: "11".repeat(64) },
      { command: "m2000800,40", reply: "22".repeat(64) },
      { command: "m2000900,8", reply: "33".repeat(8) },
    ],
    received,
  );
  const port = await listen(server);
  const controller = controllerFor(port);

  try {
    controller.initialize("session", ARM9_RANGE);
    const result = await controller.continueExecution({
      timeoutMs: 1000,
      captureContext: true,
      maxOutputBytes: 32_768,
      additionalRegions: [{ label: "extra", address: 0x02000900, length: 8 }],
    });
    assert.equal(result.kind, "stop");
    if (result.kind !== "stop") throw new Error("Expected stop result");
    assert.equal(result.context?.registers.pc, 0x02000200);
    assert.equal(result.context?.pcWindow.dataHex, "11".repeat(64));
    assert.equal(result.context?.stackWindow.dataHex, "22".repeat(64));
    assert.equal(result.context?.additionalRegions[0]?.label, "extra");
    assert.match(result.context?.capturedAt ?? "", /^\d{4}-\d{2}-\d{2}T/);
    assert.deepEqual(received, [
      "c",
      "g",
      "m20001e0,40",
      "m2000800,40",
      "m2000900,8",
    ]);
  } finally {
    await controller.reset("test cleanup");
    await close(server);
  }
});

test("step attaches context only to the final result", async () => {
  const received: string[] = [];
  const server = scriptedRspServer(
    [
      { command: "s", reply: "S05" },
      { command: "s", reply: "S05" },
      { command: "g", reply: registerPacket({ pc: 0x02000204 }) },
      { command: "m20001e4,40", reply: "00".repeat(64) },
      { command: "m2000800,40", reply: "00".repeat(64) },
    ],
    received,
  );
  const port = await listen(server);
  const controller = controllerFor(port);

  try {
    controller.initialize("session", ARM9_RANGE);
    const stepped = await controller.step({
      count: 2,
      perStepTimeoutMs: 1000,
      captureContext: true,
      maxOutputBytes: 32_768,
    });
    assert.equal(stepped.completed, 2);
    assert.equal(stepped.result.kind, "stop");
    if (stepped.result.kind !== "stop") throw new Error("Expected stop result");
    assert.equal(stepped.result.context?.registers.pc, 0x02000204);
    assert.deepEqual(received, ["s", "s", "g", "m20001e4,40", "m2000800,40"]);
  } finally {
    await controller.reset("test cleanup");
    await close(server);
  }
});

test("wait and pause use the same stop enrichment path", async () => {
  const received: string[] = [];
  let continueCount = 0;
  const server = net.createServer((socket) => {
    let buffer = "";
    socket.on("data", (chunk) => {
      if (chunk.includes(0x03)) {
        received.push("INTERRUPT");
        socket.write(encodeRspPacket("S02"), "ascii");
        return;
      }

      buffer += chunk.toString("ascii");
      for (;;) {
        const parsed = parseRspPacket(buffer);
        if (parsed === null) return;
        buffer = buffer.slice(parsed.consumed);
        received.push(parsed.payload);

        if (parsed.payload === "c") {
          continueCount += 1;
          socket.write("+", "ascii");
          if (continueCount === 1) {
            setTimeout(() => socket.write(encodeRspPacket("S05"), "ascii"), 60);
          }
          continue;
        }

        if (parsed.payload === "g") {
          const pc = continueCount === 1 ? 0x02000300 : 0x02000304;
          socket.write(`+${encodeRspPacket(registerPacket({ pc }))}`, "ascii");
        }
      }
    });
  });
  const port = await listen(server);
  const controller = controllerFor(port);

  try {
    controller.initialize("session", ARM9_RANGE);
    assert.equal(
      (await controller.continueExecution({ timeoutMs: 20, captureContext: false })).kind,
      "timeout",
    );
    const waited = await controller.waitForStop({ timeoutMs: 1000, captureContext: false });
    assert.equal(waited.kind, "stop");
    if (waited.kind !== "stop") throw new Error("Expected stop result");
    assert.equal(waited.stop.raw, "S05");

    assert.equal(
      (await controller.continueExecution({ timeoutMs: 20, captureContext: false })).kind,
      "timeout",
    );
    const paused = await controller.pause({ timeoutMs: 1000, captureContext: false });
    assert.equal(paused.kind, "stop");
    if (paused.kind !== "stop") throw new Error("Expected stop result");
    assert.equal(paused.stop.raw, "S02");
    assert.deepEqual(received, ["c", "g", "c", "INTERRUPT", "g"]);
  } finally {
    await controller.reset("test cleanup");
    await close(server);
  }
});
