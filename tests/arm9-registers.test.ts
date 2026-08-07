import assert from "node:assert/strict";
import test from "node:test";

import { decodeArm9RegisterPacket } from "../src/services/arm9-registers.js";

function littleEndianU32(value: number): string {
  const buffer = Buffer.alloc(4);
  buffer.writeUInt32LE(value >>> 0, 0);
  return buffer.toString("hex");
}

function registerPacket(options: {
  readonly registers?: readonly number[];
  readonly cpsr?: number;
  readonly floatingHex?: string;
  readonly floatingStatusHex?: string;
} = {}): string {
  const registers = options.registers ?? Array.from({ length: 16 }, (_, index) => 0x10000000 + index);
  if (registers.length !== 16) throw new Error("Test fixture requires 16 ARM registers");
  const floatingHex = options.floatingHex ?? "0".repeat(8 * 24);
  const floatingStatusHex = options.floatingStatusHex ?? "0".repeat(8);
  return [
    ...registers.map(littleEndianU32),
    floatingHex,
    floatingStatusHex,
    littleEndianU32(options.cpsr ?? 0x60000013),
  ].join("");
}

test("decodes the exact DeSmuME ARM9 register packet", () => {
  const registers = [
    0x01020304,
    0x11121314,
    0x21222324,
    0x31323334,
    0x41424344,
    0x51525354,
    0x61626364,
    0x71727374,
    0x81828384,
    0x91929394,
    0xa1a2a3a4,
    0xb1b2b3b4,
    0xc1c2c3c4,
    0x02003ff0,
    0x02000101,
    0x02000200,
  ];
  const raw = registerPacket({ registers, cpsr: 0x60000013 });

  assert.equal(raw.length, 336);
  assert.deepEqual(decodeArm9RegisterPacket(raw), {
    r0: 0x01020304,
    r1: 0x11121314,
    r2: 0x21222324,
    r3: 0x31323334,
    r4: 0x41424344,
    r5: 0x51525354,
    r6: 0x61626364,
    r7: 0x71727374,
    r8: 0x81828384,
    r9: 0x91929394,
    r10: 0xa1a2a3a4,
    r11: 0xb1b2b3b4,
    r12: 0xc1c2c3c4,
    sp: 0x02003ff0,
    lr: 0x02000101,
    pc: 0x02000200,
    cpsr: 0x60000013,
    mode: "arm",
    byteOrder: "little",
    raw,
  });
});

test("derives Thumb execution mode from CPSR bit 5", () => {
  const raw = registerPacket({ cpsr: 0x60000033 });
  const decoded = decodeArm9RegisterPacket(raw);
  assert.equal(decoded.cpsr, 0x60000033);
  assert.equal(decoded.mode, "thumb");
});

test("accepts nonzero floating-point placeholder data without exposing it", () => {
  const raw = registerPacket({
    floatingHex: "ab".repeat(8 * 12),
    floatingStatusHex: "cd".repeat(4),
  });
  const decoded = decodeArm9RegisterPacket(raw);
  assert.equal(decoded.r0, 0x10000000);
  assert.equal(decoded.pc, 0x1000000f);
  assert.equal(decoded.raw, raw);
});

test("rejects register packets that are not exactly 336 hex characters", () => {
  const raw = registerPacket();
  assert.throws(() => decodeArm9RegisterPacket(raw.slice(0, -2)), /exactly 336 hexadecimal characters/);
  assert.throws(() => decodeArm9RegisterPacket(`${raw}00`), /exactly 336 hexadecimal characters/);
});

test("rejects non-hexadecimal register packets", () => {
  const raw = registerPacket();
  const malformed = `${raw.slice(0, 80)}zz${raw.slice(82)}`;
  assert.throws(() => decodeArm9RegisterPacket(malformed), /only hexadecimal characters/);
});

test("decoding is case-insensitive and preserves the raw packet", () => {
  const raw = registerPacket({ cpsr: 0xf0000013 }).toUpperCase();
  const decoded = decodeArm9RegisterPacket(raw);
  assert.equal(decoded.r10, 0x1000000a);
  assert.equal(decoded.cpsr, 0xf0000013);
  assert.equal(decoded.raw, raw);
});
