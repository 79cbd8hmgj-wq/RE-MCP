import { NdsError } from "./errors.js";

const FAT_ENTRY_BYTES = 8;
const MAX_FAT_BYTES = 4 * 1024 * 1024;
const UINT32_MAX = 0xffff_ffff;

export interface NdsFinalFatEntry {
  readonly fileId: number;
  readonly startOffset: number;
  readonly endOffset: number;
}

function fatError(message: string): NdsError<"fat-rebuild-failed"> {
  return new NdsError("fat-rebuild-failed", message);
}

function requireUint32(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < 0 || value > UINT32_MAX) {
    throw fatError(`${label} must be an unsigned 32-bit integer`);
  }
  return value;
}

export function serializeNdsFat(
  entries: readonly NdsFinalFatEntry[],
): Buffer {
  const byteLength = entries.length * FAT_ENTRY_BYTES;
  if (!Number.isSafeInteger(byteLength) || byteLength > MAX_FAT_BYTES) {
    throw fatError(
      `Serialized FAT would be ${byteLength} bytes, above the ${MAX_FAT_BYTES}-byte limit`,
    );
  }

  const liveRanges: Array<{
    readonly fileId: number;
    readonly startOffset: number;
    readonly endOffset: number;
  }> = [];

  for (let index = 0; index < entries.length; index += 1) {
    const entry = entries[index];
    if (entry === undefined || entry.fileId !== index) {
      throw fatError(`FAT entries must be contiguous and ordered by file ID; expected file ${index}`);
    }
    const startOffset = requireUint32(entry.startOffset, `FAT file ${index} start offset`);
    const endOffset = requireUint32(entry.endOffset, `FAT file ${index} end offset`);
    if (startOffset > endOffset) {
      throw fatError(`FAT file ${index} starts after its end offset`);
    }
    if (endOffset > startOffset) {
      liveRanges.push({ fileId: index, startOffset, endOffset });
    }
  }

  liveRanges.sort(
    (left, right) => left.startOffset - right.startOffset
      || left.endOffset - right.endOffset
      || left.fileId - right.fileId,
  );
  for (let index = 1; index < liveRanges.length; index += 1) {
    const previous = liveRanges[index - 1];
    const current = liveRanges[index];
    if (previous !== undefined && current !== undefined && current.startOffset < previous.endOffset) {
      throw fatError(
        `FAT files ${previous.fileId} and ${current.fileId} overlap at ROM range 0x${current.startOffset.toString(16)}..0x${Math.min(previous.endOffset, current.endOffset).toString(16)}`,
      );
    }
  }

  const output = Buffer.alloc(byteLength);
  for (const entry of entries) {
    const base = entry.fileId * FAT_ENTRY_BYTES;
    output.writeUInt32LE(entry.startOffset, base);
    output.writeUInt32LE(entry.endOffset, base + 4);
  }
  return output;
}
