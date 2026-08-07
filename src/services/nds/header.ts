import { open, stat } from "node:fs/promises";

import { NdsError } from "./errors.js";
import { hashFileSha256, readExact } from "./io.js";

export const NDS_PARSED_HEADER_BYTES = 0x6c;
const ARM9_HEADER_BYTES = 0x30;
const UINT32_END = 0x1_0000_0000;

const OFFSETS = {
  title: 0x00,
  gameCode: 0x0c,
  makerCode: 0x10,
  unitCode: 0x12,
  deviceCapacity: 0x14,
  romVersion: 0x1e,
  arm9Rom: 0x20,
  arm9Entry: 0x24,
  arm9Ram: 0x28,
  arm9Size: 0x2c,
  arm7Rom: 0x30,
  arm7Entry: 0x34,
  arm7Ram: 0x38,
  arm7Size: 0x3c,
  fntOffset: 0x40,
  fntSize: 0x44,
  fatOffset: 0x48,
  fatSize: 0x4c,
  arm9OverlayOffset: 0x50,
  arm9OverlaySize: 0x54,
  arm7OverlayOffset: 0x58,
  arm7OverlaySize: 0x5c,
  bannerOffset: 0x68,
} as const;

export interface NdsExecutableHeader {
  readonly romOffset: number;
  readonly entryAddress: number;
  readonly ramAddress: number;
  readonly size: number;
  readonly romEnd: number;
  readonly ramEnd: number;
}

export interface NdsRegionHeader {
  readonly offset: number;
  readonly size: number;
  readonly end: number;
}

export interface NdsHeader {
  readonly gameTitle: string;
  readonly gameCode: string;
  readonly makerCode: string;
  readonly unitCode: number;
  readonly deviceCapacity: number;
  readonly romVersion: number;
  readonly bannerOffset: number;
  readonly arm9: NdsExecutableHeader;
  readonly arm7: NdsExecutableHeader;
  readonly fnt: NdsRegionHeader;
  readonly fat: NdsRegionHeader;
  readonly arm9OverlayTable: NdsRegionHeader;
  readonly arm7OverlayTable: NdsRegionHeader;
}

export interface ParsedNdsHeader {
  readonly romPath: string;
  readonly fileSize: number;
  readonly sha256: string;
  readonly sha256Prefix: string;
  readonly header: NdsHeader;
}

interface RawExecutableHeader {
  readonly romOffset: number;
  readonly entryAddress: number;
  readonly ramAddress: number;
  readonly size: number;
}

async function requireRegularFile(filePath: string, minimumBytes: number): Promise<number> {
  let info;
  try {
    info = await stat(filePath);
  } catch (error) {
    throw new NdsError(
      "invalid-rom",
      `Unable to inspect NDS ROM: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  if (!info.isFile()) {
    throw new NdsError("invalid-rom", "NDS ROM path must reference a regular file");
  }
  if (info.size < minimumBytes) {
    throw new NdsError(
      "invalid-rom",
      `NDS ROM is too short: expected at least ${minimumBytes} header bytes`,
    );
  }
  return info.size;
}

function decodeFixedAscii(buffer: Buffer, offset: number, length: number): string {
  return buffer.subarray(offset, offset + length).toString("ascii").replace(/\0+$/u, "");
}

function decodeExecutable(buffer: Buffer, base: "arm9" | "arm7"): RawExecutableHeader {
  if (base === "arm9") {
    return {
      romOffset: buffer.readUInt32LE(OFFSETS.arm9Rom),
      entryAddress: buffer.readUInt32LE(OFFSETS.arm9Entry),
      ramAddress: buffer.readUInt32LE(OFFSETS.arm9Ram),
      size: buffer.readUInt32LE(OFFSETS.arm9Size),
    };
  }
  return {
    romOffset: buffer.readUInt32LE(OFFSETS.arm7Rom),
    entryAddress: buffer.readUInt32LE(OFFSETS.arm7Entry),
    ramAddress: buffer.readUInt32LE(OFFSETS.arm7Ram),
    size: buffer.readUInt32LE(OFFSETS.arm7Size),
  };
}

function checkedExecutable(
  raw: RawExecutableHeader,
  fileSize: number,
  label: "ARM9" | "ARM7",
): NdsExecutableHeader {
  if (raw.size === 0) {
    throw new NdsError("malformed-header", `${label} size must be positive`);
  }
  const romEnd = raw.romOffset + raw.size;
  if (!Number.isSafeInteger(romEnd) || romEnd < raw.romOffset || romEnd > fileSize) {
    throw new NdsError("range-out-of-bounds", `${label} data extends beyond the ROM file`);
  }
  const ramEnd = raw.ramAddress + raw.size;
  if (!Number.isSafeInteger(ramEnd) || ramEnd <= raw.ramAddress || ramEnd > UINT32_END) {
    throw new NdsError("malformed-header", `${label} runtime range overflows 32-bit address space`);
  }
  return {
    romOffset: raw.romOffset,
    entryAddress: raw.entryAddress,
    ramAddress: raw.ramAddress,
    size: raw.size,
    romEnd,
    ramEnd,
  };
}

function checkedRegion(
  offset: number,
  size: number,
  fileSize: number,
  label: string,
): NdsRegionHeader {
  if (offset > fileSize) {
    throw new NdsError("range-out-of-bounds", `${label} offset lies beyond the ROM file`);
  }
  const end = offset + size;
  if (!Number.isSafeInteger(end) || end < offset || end > fileSize) {
    throw new NdsError("range-out-of-bounds", `${label} extends beyond the ROM file`);
  }
  return { offset, size, end };
}

export async function readArm9HeaderMetadata(romPath: string): Promise<NdsExecutableHeader> {
  const fileSize = await requireRegularFile(romPath, ARM9_HEADER_BYTES);
  const handle = await open(romPath, "r");
  try {
    const buffer = await readExact(handle, 0, ARM9_HEADER_BYTES, "NDS ARM9 header");
    return checkedExecutable(decodeExecutable(buffer, "arm9"), fileSize, "ARM9");
  } finally {
    await handle.close();
  }
}

export async function parseNdsHeader(romPath: string): Promise<ParsedNdsHeader> {
  const fileSize = await requireRegularFile(romPath, NDS_PARSED_HEADER_BYTES);
  const handle = await open(romPath, "r");
  let buffer: Buffer;
  try {
    buffer = await readExact(handle, 0, NDS_PARSED_HEADER_BYTES, "NDS header");
  } finally {
    await handle.close();
  }

  const arm9 = checkedExecutable(decodeExecutable(buffer, "arm9"), fileSize, "ARM9");
  const arm7 = checkedExecutable(decodeExecutable(buffer, "arm7"), fileSize, "ARM7");
  const fnt = checkedRegion(
    buffer.readUInt32LE(OFFSETS.fntOffset),
    buffer.readUInt32LE(OFFSETS.fntSize),
    fileSize,
    "FNT",
  );
  const fat = checkedRegion(
    buffer.readUInt32LE(OFFSETS.fatOffset),
    buffer.readUInt32LE(OFFSETS.fatSize),
    fileSize,
    "FAT",
  );
  const arm9OverlayTable = checkedRegion(
    buffer.readUInt32LE(OFFSETS.arm9OverlayOffset),
    buffer.readUInt32LE(OFFSETS.arm9OverlaySize),
    fileSize,
    "ARM9 overlay table",
  );
  const arm7OverlayTable = checkedRegion(
    buffer.readUInt32LE(OFFSETS.arm7OverlayOffset),
    buffer.readUInt32LE(OFFSETS.arm7OverlaySize),
    fileSize,
    "ARM7 overlay table",
  );
  const bannerOffset = buffer.readUInt32LE(OFFSETS.bannerOffset);
  if (bannerOffset > fileSize) {
    throw new NdsError("range-out-of-bounds", "Banner offset lies beyond the ROM file");
  }

  const sha256 = await hashFileSha256(romPath);
  return {
    romPath,
    fileSize,
    sha256,
    sha256Prefix: sha256.slice(0, 16),
    header: {
      gameTitle: decodeFixedAscii(buffer, OFFSETS.title, 12),
      gameCode: decodeFixedAscii(buffer, OFFSETS.gameCode, 4),
      makerCode: decodeFixedAscii(buffer, OFFSETS.makerCode, 2),
      unitCode: buffer.readUInt8(OFFSETS.unitCode),
      deviceCapacity: buffer.readUInt8(OFFSETS.deviceCapacity),
      romVersion: buffer.readUInt8(OFFSETS.romVersion),
      bannerOffset,
      arm9,
      arm7,
      fnt,
      fat,
      arm9OverlayTable,
      arm7OverlayTable,
    },
  };
}
