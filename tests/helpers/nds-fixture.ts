import { mkdtemp, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

export interface NdsFixtureOptions {
  readonly fileSize?: number;
  readonly arm9RomOffset?: number;
  readonly arm9RamAddress?: number;
  readonly arm9EntryAddress?: number;
  readonly arm9Size?: number;
  readonly arm7RomOffset?: number;
  readonly arm7RamAddress?: number;
  readonly arm7EntryAddress?: number;
  readonly arm7Size?: number;
  readonly fntOffset?: number;
  readonly fntSize?: number;
  readonly fatOffset?: number;
  readonly fatSize?: number;
  readonly arm9OverlayOffset?: number;
  readonly arm9OverlaySize?: number;
  readonly arm7OverlayOffset?: number;
  readonly arm7OverlaySize?: number;
  readonly bannerOffset?: number;
}

export interface NdsFixture {
  readonly directory: string;
  readonly romPath: string;
  readonly buffer: Buffer;
  write(): Promise<void>;
}

function writeAsciiFixed(buffer: Buffer, offset: number, length: number, value: string): void {
  buffer.fill(0, offset, offset + length);
  buffer.write(value.slice(0, length), offset, length, "ascii");
}

export async function createNdsFixture(
  options: NdsFixtureOptions = {},
): Promise<NdsFixture> {
  const directory = await mkdtemp(path.join(os.tmpdir(), "re-mcp-nds-fixture-"));
  const romPath = path.join(directory, "fixture.nds");
  const buffer = Buffer.alloc(options.fileSize ?? 0x4000);

  if (buffer.length >= 0x6c) {
    writeAsciiFixed(buffer, 0x00, 12, "RE-MCP TEST");
    writeAsciiFixed(buffer, 0x0c, 4, "TEST");
    writeAsciiFixed(buffer, 0x10, 2, "01");
    buffer.writeUInt8(0, 0x12);
    buffer.writeUInt8(8, 0x14);
    buffer.writeUInt8(0, 0x1e);

    buffer.writeUInt32LE(options.arm9RomOffset ?? 0x200, 0x20);
    buffer.writeUInt32LE(options.arm9EntryAddress ?? options.arm9RamAddress ?? 0x02000000, 0x24);
    buffer.writeUInt32LE(options.arm9RamAddress ?? 0x02000000, 0x28);
    buffer.writeUInt32LE(options.arm9Size ?? 0x200, 0x2c);

    buffer.writeUInt32LE(options.arm7RomOffset ?? 0x600, 0x30);
    buffer.writeUInt32LE(options.arm7EntryAddress ?? options.arm7RamAddress ?? 0x03800000, 0x34);
    buffer.writeUInt32LE(options.arm7RamAddress ?? 0x03800000, 0x38);
    buffer.writeUInt32LE(options.arm7Size ?? 0x100, 0x3c);

    buffer.writeUInt32LE(options.fntOffset ?? 0x800, 0x40);
    buffer.writeUInt32LE(options.fntSize ?? 0, 0x44);
    buffer.writeUInt32LE(options.fatOffset ?? 0x900, 0x48);
    buffer.writeUInt32LE(options.fatSize ?? 0, 0x4c);
    buffer.writeUInt32LE(options.arm9OverlayOffset ?? 0xa00, 0x50);
    buffer.writeUInt32LE(options.arm9OverlaySize ?? 0, 0x54);
    buffer.writeUInt32LE(options.arm7OverlayOffset ?? 0xb00, 0x58);
    buffer.writeUInt32LE(options.arm7OverlaySize ?? 0, 0x5c);
    buffer.writeUInt32LE(options.bannerOffset ?? 0xc00, 0x68);
  }

  const fixture: NdsFixture = {
    directory,
    romPath,
    buffer,
    async write() {
      await writeFile(romPath, buffer);
    },
  };
  await fixture.write();
  return fixture;
}

export function writeFatEntry(
  buffer: Buffer,
  fatOffset: number,
  fileId: number,
  startOffset: number,
  endOffset: number,
): void {
  const base = fatOffset + fileId * 8;
  buffer.writeUInt32LE(startOffset, base);
  buffer.writeUInt32LE(endOffset, base + 4);
}

export function writeFntMainRecord(
  buffer: Buffer,
  fntOffset: number,
  index: number,
  subtableOffset: number,
  firstFileId: number,
  parentOrDirectoryCount: number,
): void {
  const base = fntOffset + index * 8;
  buffer.writeUInt32LE(subtableOffset, base);
  buffer.writeUInt16LE(firstFileId, base + 4);
  buffer.writeUInt16LE(parentOrDirectoryCount, base + 6);
}

export function encodeFntFileEntry(name: string): Buffer {
  const bytes = Buffer.from(name, "latin1");
  if (bytes.length < 1 || bytes.length > 0x7f) {
    throw new Error("FNT file name must contain 1..127 bytes");
  }
  return Buffer.concat([Buffer.from([bytes.length]), bytes]);
}

export function encodeFntDirectoryEntry(name: string, childDirectoryId: number): Buffer {
  const bytes = Buffer.from(name, "latin1");
  if (bytes.length < 1 || bytes.length > 0x7f) {
    throw new Error("FNT directory name must contain 1..127 bytes");
  }
  const suffix = Buffer.alloc(2);
  suffix.writeUInt16LE(childDirectoryId, 0);
  return Buffer.concat([Buffer.from([0x80 | bytes.length]), bytes, suffix]);
}

export function writeFntSubtable(
  buffer: Buffer,
  fntOffset: number,
  subtableOffset: number,
  entries: readonly Buffer[],
  terminate = true,
): number {
  let cursor = fntOffset + subtableOffset;
  for (const entry of entries) {
    entry.copy(buffer, cursor);
    cursor += entry.length;
  }
  if (terminate) {
    buffer.writeUInt8(0, cursor);
    cursor += 1;
  }
  return cursor - fntOffset;
}
