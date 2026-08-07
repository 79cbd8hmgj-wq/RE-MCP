import assert from "node:assert/strict";
import { mkdtemp, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { readArm9ExecutableRange } from "../src/services/nds-arm9.js";

async function writeRom(options: {
  romOffset?: number;
  ramAddress?: number;
  size?: number;
  fileSize?: number;
} = {}): Promise<string> {
  const directory = await mkdtemp(path.join(os.tmpdir(), "re-mcp-nds-"));
  const romPath = path.join(directory, "test.nds");
  const fileSize = options.fileSize ?? 0x400;
  const buffer = Buffer.alloc(fileSize);
  if (fileSize >= 0x30) {
    buffer.writeUInt32LE(options.romOffset ?? 0x100, 0x20);
    buffer.writeUInt32LE(options.ramAddress ?? 0x02000000, 0x28);
    buffer.writeUInt32LE(options.size ?? 0x200, 0x2c);
  }
  await writeFile(romPath, buffer);
  return romPath;
}

test("derives the main ARM9 executable range", async () => {
  const romPath = await writeRom();
  assert.deepEqual(await readArm9ExecutableRange(romPath), {
    start: 0x02000000,
    end: 0x02000200,
    size: 0x200,
    source: "arm9-header",
    label: "ARM9 main",
  });
});

test("rejects a short ROM header", async () => {
  const romPath = await writeRom({ fileSize: 0x20 });
  await assert.rejects(readArm9ExecutableRange(romPath), /too short/);
});

test("rejects zero size and out-of-range RAM addresses", async () => {
  await assert.rejects(
    readArm9ExecutableRange(await writeRom({ size: 0 })),
    /size must be positive/,
  );
  await assert.rejects(
    readArm9ExecutableRange(await writeRom({ ramAddress: 0x01000000 })),
    /outside DS main RAM/,
  );
  await assert.rejects(
    readArm9ExecutableRange(await writeRom({ ramAddress: 0x023fff00, size: 0x200 })),
    /outside DS main RAM/,
  );
});

test("rejects ARM9 data beyond the ROM file", async () => {
  await assert.rejects(
    readArm9ExecutableRange(await writeRom({ romOffset: 0x300, size: 0x200, fileSize: 0x400 })),
    /extends beyond the ROM file/,
  );
});