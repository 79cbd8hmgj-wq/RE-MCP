import assert from "node:assert/strict";
import test from "node:test";

import { encodeRspPacket } from "../src/services/gdb-rsp.js";
import type { GdbStopReply } from "../src/services/gdb-stop.js";
import { captureStopContext } from "../src/services/stop-context.js";

function littleEndianU32(value: number): string {
  const buffer = Buffer.alloc(4);
  buffer.writeUInt32LE(value >>> 0, 0);
  return buffer.toString("hex");
}

function registerPacket(options: {
  readonly pc?: number;
  readonly sp?: number;
  readonly cpsr?: number;
} = {}): string {
  const registers = Array.from({ length: 16 }, (_, index) => 0x10000000 + index);
  registers[13] = options.sp ?? 0x02001000;
  registers[15] = options.pc ?? 0x02002000;
  return [
    ...registers.map(littleEndianU32),
    "0".repeat(8 * 24),
    "0".repeat(8),
    littleEndianU32(options.cpsr ?? 0x60000013),
  ].join("");
}

class FakeStoppedSession {
  readonly commands: string[] = [];
  readonly #registerHex: string;
  readonly #memoryReplies: Readonly<Record<string, string>>;

  constructor(
    registerHex: string,
    memoryReplies: Readonly<Record<string, string>> = {},
  ) {
    this.#registerHex = registerHex;
    this.#memoryReplies = memoryReplies;
  }

  async sendStoppedCommand(command: string, _timeoutMs: number): Promise<string> {
    this.commands.push(command);
    if (command === "g") return this.#registerHex;
    return this.#memoryReplies[command] ?? "00".repeat(parseInt(command.split(",")[1] ?? "0", 16));
  }
}

const STOP: GdbStopReply = {
  kind: "signal",
  signal: 5,
  fields: {},
  raw: "S05",
};

test("captures registers, PC window, stack window, and additional regions", async () => {
  const session = new FakeStoppedSession(registerPacket());
  const context = await captureStopContext({
    session,
    stop: STOP,
    timeoutMs: 1000,
    maxOutputBytes: 32_768,
    additionalRegions: [
      { label: "battle", address: 0x02003000, length: 16 },
    ],
  });

  assert.equal(context.stop, STOP);
  assert.equal(context.registers.pc, 0x02002000);
  assert.equal(context.registers.sp, 0x02001000);
  assert.deepEqual(context.pcWindow, {
    address: 0x02001fe0,
    length: 64,
    dataHex: "00".repeat(64),
  });
  assert.deepEqual(context.stackWindow, {
    address: 0x02001000,
    length: 64,
    dataHex: "00".repeat(64),
  });
  assert.deepEqual(context.additionalRegions, [
    {
      label: "battle",
      address: 0x02003000,
      length: 16,
      dataHex: "00".repeat(16),
    },
  ]);
  assert.deepEqual(session.commands, [
    "g",
    "m2001fe0,40",
    "m2001000,40",
    "m2003000,10",
  ]);
});

test("clamps the PC window at unsigned address-space boundaries", async () => {
  const low = new FakeStoppedSession(registerPacket({ pc: 0x10 }));
  const lowContext = await captureStopContext({
    session: low,
    stop: STOP,
    timeoutMs: 1000,
    maxOutputBytes: 32_768,
  });
  assert.deepEqual(lowContext.pcWindow, {
    address: 0,
    length: 48,
    dataHex: "00".repeat(48),
  });

  const high = new FakeStoppedSession(registerPacket({ pc: 0xfffffff0 }));
  const highContext = await captureStopContext({
    session: high,
    stop: STOP,
    timeoutMs: 1000,
    maxOutputBytes: 32_768,
  });
  assert.deepEqual(highContext.pcWindow, {
    address: 0xffffffd0,
    length: 48,
    dataHex: "00".repeat(48),
  });
});

test("clamps the stack read at the top of unsigned address space", async () => {
  const session = new FakeStoppedSession(registerPacket({ sp: 0xfffffff0 }));
  const context = await captureStopContext({
    session,
    stop: STOP,
    timeoutMs: 1000,
    maxOutputBytes: 32_768,
  });
  assert.deepEqual(context.stackWindow, {
    address: 0xfffffff0,
    length: 16,
    dataHex: "00".repeat(16),
  });
});

test("rejects more than eight additional regions", async () => {
  const session = new FakeStoppedSession(registerPacket());
  await assert.rejects(
    captureStopContext({
      session,
      stop: STOP,
      timeoutMs: 1000,
      maxOutputBytes: 32_768,
      additionalRegions: Array.from({ length: 9 }, (_, index) => ({
        label: `region-${index}`,
        address: 0x02003000 + index * 0x100,
        length: 4,
      })),
    }),
    /at most 8 additional memory regions/,
  );
});

test("rejects invalid additional-region labels and oversized reads", async () => {
  const session = new FakeStoppedSession(registerPacket());
  await assert.rejects(
    captureStopContext({
      session,
      stop: STOP,
      timeoutMs: 1000,
      maxOutputBytes: 32_768,
      additionalRegions: [{ label: "bad label", address: 0x02003000, length: 4 }],
    }),
    /Invalid stop-context region label/,
  );
  await assert.rejects(
    captureStopContext({
      session,
      stop: STOP,
      timeoutMs: 1000,
      maxOutputBytes: 32_768,
      additionalRegions: [{ label: "large", address: 0x02003000, length: 4097 }],
    }),
    /1 through 4096/,
  );
});

test("reports GDB memory errors with the failing region", async () => {
  const session = new FakeStoppedSession(registerPacket(), {
    "m2001fe0,40": "E03",
  });
  await assert.rejects(
    captureStopContext({
      session,
      stop: STOP,
      timeoutMs: 1000,
      maxOutputBytes: 32_768,
    }),
    /GDB memory read failed for PC window: E03/,
  );
});

test("rejects malformed memory reply lengths", async () => {
  const session = new FakeStoppedSession(registerPacket(), {
    "m2001fe0,40": "00",
  });
  await assert.rejects(
    captureStopContext({
      session,
      stop: STOP,
      timeoutMs: 1000,
      maxOutputBytes: 32_768,
    }),
    /PC window returned 1 byte; expected 64/,
  );
});

test("enforces the serialized stop-context output limit", async () => {
  const session = new FakeStoppedSession(registerPacket());
  await assert.rejects(
    captureStopContext({
      session,
      stop: STOP,
      timeoutMs: 1000,
      maxOutputBytes: 256,
    }),
    /Stop context exceeds configured output limit/,
  );
});
