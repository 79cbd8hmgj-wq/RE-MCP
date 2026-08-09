import assert from "node:assert/strict";
import { mkdtemp, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { NdsError } from "../src/services/nds/errors.js";
import {
  crc16NdsHeader,
  ndsCapacityBytes,
  readNdsRebuildHeader,
  selectNdsDeviceCapacity,
  serializeNdsRebuildHeader,
} from "../src/services/nds/header-rebuild.js";

const HEADER_BYTES = 0x160;
const HEADER_CRC_OFFSET = 0x15e;

function referenceCrc16(bytes: Uint8Array): number {
  let crc = 0xffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) {
      crc = (crc & 1) !== 0 ? (crc >>> 1) ^ 0xa001 : crc >>> 1;
    }
  }
  return crc & 0xffff;
}

function validHeader(fillSentinels = false): Buffer {
  const header = Buffer.alloc(HEADER_BYTES);
  if (fillSentinels) {
    for (let index = 0; index < header.length; index += 1) {
      header[index] = (index * 29 + 7) & 0xff;
    }
  }
  header.writeUInt8(8, 0x14);
  header.writeUInt32LE(0x800, 0x40);
  header.writeUInt32LE(0x60, 0x44);
  header.writeUInt32LE(0x900, 0x48);
  header.writeUInt32LE(0x18, 0x4c);
  header.writeUInt32LE(0xa00, 0x50);
  header.writeUInt32LE(0x40, 0x54);
  header.writeUInt32LE(0xb00, 0x58);
  header.writeUInt32LE(0, 0x5c);
  header.writeUInt32LE(0x6000, 0x80);
  header.writeUInt32LE(0x4000, 0x84);
  header.writeUInt16LE(referenceCrc16(header.subarray(0, HEADER_CRC_OFFSET)), HEADER_CRC_OFFSET);
  return header;
}

async function writeHeaderFixture(header: Buffer): Promise<string> {
  const directory = await mkdtemp(path.join(os.tmpdir(), "re-mcp-header-rebuild-"));
  const romPath = path.join(directory, "fixture.nds");
  await writeFile(romPath, Buffer.concat([header, Buffer.alloc(0x100)]));
  return romPath;
}

test("computes the Nintendo DS header CRC16 deterministically", () => {
  const vector = Buffer.alloc(0x15e);
  for (let index = 0; index < vector.length; index += 1) {
    vector[index] = (index * 37 + 11) & 0xff;
  }
  assert.equal(referenceCrc16(vector), 0x7191);
  assert.equal(crc16NdsHeader(vector), 0x7191);

  const changed = Buffer.from(vector);
  changed[0x40] ^= 0x01;
  assert.notEqual(crc16NdsHeader(changed), 0x7191);
});

test("selects the smallest bounded NDS device capacity", () => {
  assert.equal(ndsCapacityBytes(0), 128 * 1024);
  assert.equal(ndsCapacityBytes(1), 256 * 1024);
  assert.deepEqual(selectNdsDeviceCapacity(128 * 1024), {
    deviceCapacity: 0,
    capacityBytes: 128 * 1024,
  });
  assert.deepEqual(selectNdsDeviceCapacity((128 * 1024) + 1), {
    deviceCapacity: 1,
    capacityBytes: 256 * 1024,
  });
  assert.deepEqual(selectNdsDeviceCapacity(512 * 1024 * 1024), {
    deviceCapacity: 12,
    capacityBytes: 512 * 1024 * 1024,
  });

  for (const invalid of [0, -1, Number.MAX_SAFE_INTEGER, (512 * 1024 * 1024) + 1]) {
    assert.throws(
      () => selectNdsDeviceCapacity(invalid),
      (error: unknown) => error instanceof NdsError
        && error.category === "rom-capacity-exceeded",
    );
  }
});

test("reads a rebuild-critical header only when its stored CRC is valid", async () => {
  const header = validHeader();
  const romPath = await writeHeaderFixture(header);
  const snapshot = await readNdsRebuildHeader(romPath);
  assert.deepEqual(snapshot.bytes, header);
  assert.equal(snapshot.deviceCapacity, 8);
  assert.equal(snapshot.romUsedSize, 0x6000);
  assert.equal(snapshot.headerSize, 0x4000);
  assert.equal(snapshot.headerCrc16, header.readUInt16LE(HEADER_CRC_OFFSET));

  const corrupt = Buffer.from(header);
  corrupt[0x40] ^= 0x01;
  const corruptPath = await writeHeaderFixture(corrupt);
  await assert.rejects(
    readNdsRebuildHeader(corruptPath),
    (error: unknown) => error instanceof NdsError
      && error.category === "header-checksum-invalid",
  );
});

test("rewrites only owned header fields and recomputes CRC", async () => {
  const header = validHeader(true);
  const romPath = await writeHeaderFixture(header);
  const source = await readNdsRebuildHeader(romPath);
  const output = serializeNdsRebuildHeader(source, {
    deviceCapacity: 9,
    romUsedSize: 0x123456,
    fat: { offset: 0x22000, size: 0x80 },
  });

  assert.equal(output.readUInt8(0x14), 9);
  assert.equal(output.readUInt32LE(0x48), 0x22000);
  assert.equal(output.readUInt32LE(0x4c), 0x80);
  assert.equal(output.readUInt32LE(0x80), 0x123456);
  assert.equal(output.readUInt16LE(HEADER_CRC_OFFSET), referenceCrc16(output.subarray(0, HEADER_CRC_OFFSET)));

  const allowed = new Set<number>([
    0x14,
    0x48, 0x49, 0x4a, 0x4b,
    0x4c, 0x4d, 0x4e, 0x4f,
    0x80, 0x81, 0x82, 0x83,
    0x15e, 0x15f,
  ]);
  for (let index = 0; index < HEADER_BYTES; index += 1) {
    if (!allowed.has(index)) {
      assert.equal(output[index], header[index], `unowned header byte 0x${index.toString(16)} changed`);
    }
  }
  assert.deepEqual(source.bytes, header, "serializer mutated the source header snapshot");
});
