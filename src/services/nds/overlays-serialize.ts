import { NdsError } from "./errors.js";
import type { NdsOverlay } from "./overlays.js";

const OVERLAY_RECORD_BYTES = 32;
const MAX_PACKED_COMPRESSED_SIZE = 0x00ff_ffff;

function rebuildFailed(message: string): never {
  throw new NdsError("overlay-table-rebuild-failed", message);
}

export function serializeNdsOverlayTable(
  source: readonly NdsOverlay[],
  compressedSizeOverrides: ReadonlyMap<number, number>,
): Buffer {
  const sourceIds = new Set<number>();
  for (const overlay of source) {
    if (sourceIds.has(overlay.overlayId)) {
      rebuildFailed(`Overlay table contains duplicate overlay ID ${overlay.overlayId}`);
    }
    sourceIds.add(overlay.overlayId);
  }

  for (const [overlayId, compressedSize] of compressedSizeOverrides) {
    if (!sourceIds.has(overlayId)) {
      rebuildFailed(`Compressed-size override references unknown overlay ID ${overlayId}`);
    }
    if (
      !Number.isSafeInteger(compressedSize)
      || compressedSize < 1
      || compressedSize > MAX_PACKED_COMPRESSED_SIZE
    ) {
      if (compressedSize > MAX_PACKED_COMPRESSED_SIZE) {
        throw new NdsError(
          "blz-packed-size-overflow",
          `Overlay ${overlayId} encoded BLZ size ${compressedSize} exceeds the 24-bit overlay-table field`,
        );
      }
      rebuildFailed(`Overlay ${overlayId} compressed-size override ${compressedSize} is invalid`);
    }
  }

  const output = Buffer.alloc(source.length * OVERLAY_RECORD_BYTES);
  for (let index = 0; index < source.length; index += 1) {
    const overlay = source[index]!;
    const base = index * OVERLAY_RECORD_BYTES;
    const compressedSize = compressedSizeOverrides.get(overlay.overlayId)
      ?? overlay.compressedSize;
    if (compressedSize < 0 || compressedSize > MAX_PACKED_COMPRESSED_SIZE) {
      rebuildFailed(
        `Source overlay ${overlay.overlayId} compressed size ${compressedSize} cannot be serialized`,
      );
    }

    output.writeUInt32LE(overlay.overlayId >>> 0, base);
    output.writeUInt32LE(overlay.ramAddress >>> 0, base + 0x04);
    output.writeUInt32LE(overlay.ramSize >>> 0, base + 0x08);
    output.writeUInt32LE(overlay.bssSize >>> 0, base + 0x0c);
    output.writeUInt32LE(overlay.staticInitStart >>> 0, base + 0x10);
    output.writeUInt32LE(overlay.staticInitEnd >>> 0, base + 0x14);
    output.writeUInt32LE(overlay.fileId >>> 0, base + 0x18);
    output.writeUInt32LE(
      (((overlay.flags & 0xff) << 24) | compressedSize) >>> 0,
      base + 0x1c,
    );
  }
  return output;
}
