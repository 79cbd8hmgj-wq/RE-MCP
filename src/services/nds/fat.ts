import { open } from "node:fs/promises";

import { NdsError } from "./errors.js";
import type { ParsedNdsHeader } from "./header.js";
import { readExact } from "./io.js";

export interface NdsFatEntry {
  readonly fileId: number;
  readonly startOffset: number;
  readonly endOffset: number;
  readonly size: number;
}

export async function parseNdsFat(
  parsed: ParsedNdsHeader,
): Promise<readonly NdsFatEntry[]> {
  const region = parsed.header.fat;
  if (region.size === 0) {
    return [];
  }
  if (region.size % 8 !== 0) {
    throw new NdsError("malformed-fat", "NDS FAT size must be divisible by 8");
  }

  const handle = await open(parsed.romPath, "r");
  let buffer: Buffer;
  try {
    buffer = await readExact(handle, region.offset, region.size, "NDS FAT");
  } finally {
    await handle.close();
  }

  const entries: NdsFatEntry[] = [];
  const count = region.size / 8;
  for (let fileId = 0; fileId < count; fileId += 1) {
    const base = fileId * 8;
    const startOffset = buffer.readUInt32LE(base);
    const endOffset = buffer.readUInt32LE(base + 4);
    if (startOffset > endOffset) {
      throw new NdsError(
        "malformed-fat",
        `FAT file ${fileId} starts after its end offset`,
      );
    }
    if (startOffset > parsed.fileSize || endOffset > parsed.fileSize) {
      throw new NdsError(
        "range-out-of-bounds",
        `FAT file ${fileId} extends beyond the ROM file`,
      );
    }
    entries.push({
      fileId,
      startOffset,
      endOffset,
      size: endOffset - startOffset,
    });
  }
  return entries;
}
