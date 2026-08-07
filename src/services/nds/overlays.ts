import { open } from "node:fs/promises";

import { NdsError } from "./errors.js";
import type { NdsFatEntry } from "./fat.js";
import type { NdsRegionHeader, ParsedNdsHeader } from "./header.js";
import { readExact } from "./io.js";

const OVERLAY_RECORD_BYTES = 32;
const UINT32_END = 0x1_0000_0000;

export type NdsProcessor = "arm9" | "arm7";

export interface NdsOverlay {
  readonly processor: NdsProcessor;
  readonly overlayId: number;
  readonly ramAddress: number;
  readonly ramSize: number;
  readonly ramEnd: number;
  readonly bssSize: number;
  readonly bssEnd: number;
  readonly staticInitStart: number;
  readonly staticInitEnd: number;
  readonly fileId: number;
  readonly romOffset: number;
  readonly romSize: number;
  readonly compressedSize: number;
  readonly flags: number;
  readonly compressed: boolean;
}

function tableRegion(parsed: ParsedNdsHeader, processor: NdsProcessor): NdsRegionHeader {
  return processor === "arm9"
    ? parsed.header.arm9OverlayTable
    : parsed.header.arm7OverlayTable;
}

function checkedAddressEnd(
  start: number,
  size: number,
  label: string,
): number {
  const end = start + size;
  if (!Number.isSafeInteger(end) || end < start || end > UINT32_END) {
    throw new NdsError(
      "malformed-overlay-table",
      `${label} overflows 32-bit address space`,
    );
  }
  return end;
}

function validateStaticInit(
  start: number,
  end: number,
  ramAddress: number,
  ramEnd: number,
  overlayId: number,
): void {
  if (start === 0 && end === 0) {
    return;
  }
  if (
    start > end
    || start < ramAddress
    || end < ramAddress
    || start > ramEnd
    || end > ramEnd
  ) {
    throw new NdsError(
      "malformed-overlay-table",
      `Overlay ${overlayId} has an invalid static initializer range`,
    );
  }
}

export async function parseNdsOverlays(
  parsed: ParsedNdsHeader,
  fat: readonly NdsFatEntry[],
  processor: NdsProcessor,
): Promise<readonly NdsOverlay[]> {
  const region = tableRegion(parsed, processor);
  if (region.size === 0) {
    return [];
  }
  if (region.size % OVERLAY_RECORD_BYTES !== 0) {
    throw new NdsError(
      "malformed-overlay-table",
      `${processor.toUpperCase()} overlay table size must be divisible by 32`,
    );
  }

  const handle = await open(parsed.romPath, "r");
  let buffer: Buffer;
  try {
    buffer = await readExact(
      handle,
      region.offset,
      region.size,
      `${processor.toUpperCase()} overlay table`,
    );
  } finally {
    await handle.close();
  }

  const overlays: NdsOverlay[] = [];
  const count = region.size / OVERLAY_RECORD_BYTES;
  for (let index = 0; index < count; index += 1) {
    const base = index * OVERLAY_RECORD_BYTES;
    const overlayId = buffer.readUInt32LE(base);
    const ramAddress = buffer.readUInt32LE(base + 0x04);
    const ramSize = buffer.readUInt32LE(base + 0x08);
    const bssSize = buffer.readUInt32LE(base + 0x0c);
    const staticInitStart = buffer.readUInt32LE(base + 0x10);
    const staticInitEnd = buffer.readUInt32LE(base + 0x14);
    const fileId = buffer.readUInt32LE(base + 0x18);
    const packed = buffer.readUInt32LE(base + 0x1c);

    const backing = fat[fileId];
    if (backing === undefined) {
      throw new NdsError(
        "malformed-overlay-table",
        `${processor.toUpperCase()} overlay ${overlayId} references missing FAT file ${fileId}`,
      );
    }

    const ramEnd = checkedAddressEnd(
      ramAddress,
      ramSize,
      `${processor.toUpperCase()} overlay ${overlayId} initialized range`,
    );
    const bssEnd = checkedAddressEnd(
      ramEnd,
      bssSize,
      `${processor.toUpperCase()} overlay ${overlayId} BSS range`,
    );
    validateStaticInit(
      staticInitStart,
      staticInitEnd,
      ramAddress,
      ramEnd,
      overlayId,
    );

    const compressedSize = packed & 0x00ffffff;
    const flags = packed >>> 24;
    overlays.push({
      processor,
      overlayId,
      ramAddress,
      ramSize,
      ramEnd,
      bssSize,
      bssEnd,
      staticInitStart,
      staticInitEnd,
      fileId,
      romOffset: backing.startOffset,
      romSize: backing.size,
      compressedSize,
      flags,
      compressed: (flags & 1) !== 0,
    });
  }

  return overlays;
}
