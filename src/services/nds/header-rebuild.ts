import { lstat, open } from "node:fs/promises";

import { NdsError } from "./errors.js";
import { readExact } from "./io.js";

export const NDS_REBUILD_HEADER_BYTES = 0x160;
export const MAX_NDS_REBUILT_ROM_BYTES = 512 * 1024 * 1024;

const HEADER_CRC_OFFSET = 0x15e;
const DEVICE_CAPACITY_OFFSET = 0x14;
const ROM_USED_SIZE_OFFSET = 0x80;
const HEADER_SIZE_OFFSET = 0x84;
const BASE_CAPACITY_BYTES = 128 * 1024;
const MAX_DEVICE_CAPACITY = 12;
const UINT32_MAX = 0xffff_ffff;

const REGION_OFFSETS = {
  fnt: 0x40,
  fat: 0x48,
  arm9OverlayTable: 0x50,
  arm7OverlayTable: 0x58,
} as const;

export interface NdsRebuildHeaderSnapshot {
  readonly bytes: Buffer;
  readonly deviceCapacity: number;
  readonly romUsedSize: number;
  readonly headerSize: number;
  readonly headerCrc16: number;
}

export interface NdsOwnedHeaderRegionRewrite {
  readonly offset: number;
  readonly size: number;
}

export interface NdsOwnedHeaderRewriteInput {
  readonly deviceCapacity: number;
  readonly romUsedSize: number;
  readonly fnt?: NdsOwnedHeaderRegionRewrite;
  readonly fat?: NdsOwnedHeaderRegionRewrite;
  readonly arm9OverlayTable?: NdsOwnedHeaderRegionRewrite;
  readonly arm7OverlayTable?: NdsOwnedHeaderRegionRewrite;
}

function capacityError(message: string): NdsError<"rom-capacity-exceeded"> {
  return new NdsError("rom-capacity-exceeded", message);
}

function headerError(message: string): NdsError<"header-rebuild-failed"> {
  return new NdsError("header-rebuild-failed", message);
}

function requireUint32(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < 0 || value > UINT32_MAX) {
    throw headerError(`${label} must be an unsigned 32-bit integer`);
  }
  return value;
}

function validateRegion(
  region: NdsOwnedHeaderRegionRewrite,
  label: string,
): NdsOwnedHeaderRegionRewrite {
  const offset = requireUint32(region.offset, `${label} offset`);
  const size = requireUint32(region.size, `${label} size`);
  const end = offset + size;
  if (!Number.isSafeInteger(end) || end > 0x1_0000_0000) {
    throw headerError(`${label} range overflows unsigned 32-bit ROM geometry`);
  }
  return { offset, size };
}

export function crc16NdsHeader(bytes: Uint8Array): number {
  let crc = 0xffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) {
      crc = (crc & 1) !== 0
        ? (crc >>> 1) ^ 0xa001
        : crc >>> 1;
    }
  }
  return crc & 0xffff;
}

export function ndsCapacityBytes(deviceCapacity: number): number {
  if (
    !Number.isSafeInteger(deviceCapacity)
    || deviceCapacity < 0
    || deviceCapacity > MAX_DEVICE_CAPACITY
  ) {
    throw capacityError(
      `NDS device-capacity code ${deviceCapacity} is outside the supported 0..${MAX_DEVICE_CAPACITY} range`,
    );
  }
  const bytes = BASE_CAPACITY_BYTES * (2 ** deviceCapacity);
  if (!Number.isSafeInteger(bytes) || bytes > MAX_NDS_REBUILT_ROM_BYTES) {
    throw capacityError(
      `NDS device-capacity code ${deviceCapacity} exceeds the ${MAX_NDS_REBUILT_ROM_BYTES}-byte rebuild limit`,
    );
  }
  return bytes;
}

export function selectNdsDeviceCapacity(logicalUsedSize: number): {
  readonly deviceCapacity: number;
  readonly capacityBytes: number;
} {
  if (
    !Number.isSafeInteger(logicalUsedSize)
    || logicalUsedSize < 1
    || logicalUsedSize > MAX_NDS_REBUILT_ROM_BYTES
  ) {
    throw capacityError(
      `Logical NDS ROM size ${logicalUsedSize} must be a positive safe integer no larger than ${MAX_NDS_REBUILT_ROM_BYTES} bytes`,
    );
  }

  for (let deviceCapacity = 0; deviceCapacity <= MAX_DEVICE_CAPACITY; deviceCapacity += 1) {
    const capacityBytes = ndsCapacityBytes(deviceCapacity);
    if (logicalUsedSize <= capacityBytes) {
      return { deviceCapacity, capacityBytes };
    }
  }
  throw capacityError(`No supported NDS device capacity can contain ${logicalUsedSize} bytes`);
}

export async function readNdsRebuildHeader(
  romPath: string,
): Promise<NdsRebuildHeaderSnapshot> {
  let info;
  try {
    info = await lstat(romPath);
  } catch (error) {
    throw headerError(
      `Unable to inspect rebuild-critical NDS header: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  if (!info.isFile() || info.isSymbolicLink()) {
    throw headerError("Rebuild-critical NDS header must come from a regular non-symlink ROM file");
  }
  if (info.size < NDS_REBUILD_HEADER_BYTES) {
    throw headerError(
      `NDS ROM is too short for the ${NDS_REBUILD_HEADER_BYTES}-byte rebuild-critical header`,
    );
  }

  const handle = await open(romPath, "r");
  let bytes: Buffer;
  try {
    bytes = await readExact(
      handle,
      0,
      NDS_REBUILD_HEADER_BYTES,
      "NDS rebuild-critical header",
    );
  } finally {
    await handle.close();
  }

  const storedCrc = bytes.readUInt16LE(HEADER_CRC_OFFSET);
  const calculatedCrc = crc16NdsHeader(bytes.subarray(0, HEADER_CRC_OFFSET));
  if (storedCrc !== calculatedCrc) {
    throw new NdsError(
      "header-checksum-invalid",
      `NDS header CRC16 is 0x${storedCrc.toString(16).padStart(4, "0")}, expected 0x${calculatedCrc.toString(16).padStart(4, "0")}`,
    );
  }

  return {
    bytes: Buffer.from(bytes),
    deviceCapacity: bytes.readUInt8(DEVICE_CAPACITY_OFFSET),
    romUsedSize: bytes.readUInt32LE(ROM_USED_SIZE_OFFSET),
    headerSize: bytes.readUInt32LE(HEADER_SIZE_OFFSET),
    headerCrc16: storedCrc,
  };
}

function rewriteRegion(
  output: Buffer,
  base: number,
  region: NdsOwnedHeaderRegionRewrite | undefined,
  label: string,
): void {
  if (region === undefined) {
    return;
  }
  const validated = validateRegion(region, label);
  output.writeUInt32LE(validated.offset, base);
  output.writeUInt32LE(validated.size, base + 4);
}

export function serializeNdsRebuildHeader(
  source: NdsRebuildHeaderSnapshot,
  rewrites: NdsOwnedHeaderRewriteInput,
): Buffer {
  if (source.bytes.length !== NDS_REBUILD_HEADER_BYTES) {
    throw headerError(
      `Source rebuild header must contain exactly ${NDS_REBUILD_HEADER_BYTES} bytes`,
    );
  }
  const sourceCrc = crc16NdsHeader(source.bytes.subarray(0, HEADER_CRC_OFFSET));
  if (source.bytes.readUInt16LE(HEADER_CRC_OFFSET) !== sourceCrc) {
    throw new NdsError(
      "header-checksum-invalid",
      "Source rebuild header snapshot no longer has a valid CRC16",
    );
  }

  ndsCapacityBytes(rewrites.deviceCapacity);
  const romUsedSize = requireUint32(rewrites.romUsedSize, "Logical NDS ROM size");
  if (romUsedSize < 1 || romUsedSize > MAX_NDS_REBUILT_ROM_BYTES) {
    throw capacityError(
      `Logical NDS ROM size ${romUsedSize} must be between 1 and ${MAX_NDS_REBUILT_ROM_BYTES} bytes`,
    );
  }
  if (romUsedSize > ndsCapacityBytes(rewrites.deviceCapacity)) {
    throw capacityError(
      `Logical NDS ROM size ${romUsedSize} exceeds device capacity ${ndsCapacityBytes(rewrites.deviceCapacity)}`,
    );
  }

  const output = Buffer.from(source.bytes);
  output.writeUInt8(rewrites.deviceCapacity, DEVICE_CAPACITY_OFFSET);
  output.writeUInt32LE(romUsedSize, ROM_USED_SIZE_OFFSET);
  rewriteRegion(output, REGION_OFFSETS.fnt, rewrites.fnt, "FNT");
  rewriteRegion(output, REGION_OFFSETS.fat, rewrites.fat, "FAT");
  rewriteRegion(
    output,
    REGION_OFFSETS.arm9OverlayTable,
    rewrites.arm9OverlayTable,
    "ARM9 overlay table",
  );
  rewriteRegion(
    output,
    REGION_OFFSETS.arm7OverlayTable,
    rewrites.arm7OverlayTable,
    "ARM7 overlay table",
  );

  const crc = crc16NdsHeader(output.subarray(0, HEADER_CRC_OFFSET));
  output.writeUInt16LE(crc, HEADER_CRC_OFFSET);
  return output;
}
