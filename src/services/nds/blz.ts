import { NdsError } from "./errors.js";

export interface NdsBlzLimits {
  readonly maxStoredBytes: number;
  readonly maxDecodedBytes: number;
}

export interface NdsBlzDecodeResult {
  readonly bytes: Buffer;
  readonly storedSize: number;
  readonly decodedSize: number;
  readonly headerSize: number;
  readonly encodedRegionSize: number;
}

const MAX_OVERLAY_BYTES = 16 * 1024 * 1024;

export const DEFAULT_NDS_BLZ_LIMITS: NdsBlzLimits = {
  maxStoredBytes: MAX_OVERLAY_BYTES,
  maxDecodedBytes: MAX_OVERLAY_BYTES,
};

function malformed(message: string): never {
  throw new NdsError("malformed-blz", message);
}

function outputLimit(message: string): never {
  throw new NdsError("blz-output-limit", message);
}

function validatePositiveLimit(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value < 1) {
    outputLimit(`${label} must be a positive safe integer`);
  }
}

export function decodeNdsBlz(
  stored: Buffer,
  expectedDecodedSize: number,
  limits: NdsBlzLimits = DEFAULT_NDS_BLZ_LIMITS,
): NdsBlzDecodeResult {
  validatePositiveLimit(limits.maxStoredBytes, "maxStoredBytes");
  validatePositiveLimit(limits.maxDecodedBytes, "maxDecodedBytes");

  if (!Number.isSafeInteger(expectedDecodedSize) || expectedDecodedSize < 1) {
    throw new NdsError(
      "blz-output-size-mismatch",
      "Expected NDS BLZ decoded size must be a positive safe integer",
    );
  }
  if (stored.length > limits.maxStoredBytes) {
    outputLimit(
      `NDS BLZ input is ${stored.length} bytes, above the ${limits.maxStoredBytes}-byte stored limit`,
    );
  }
  if (expectedDecodedSize > limits.maxDecodedBytes) {
    outputLimit(
      `NDS BLZ output would be ${expectedDecodedSize} bytes, above the ${limits.maxDecodedBytes}-byte decoded limit`,
    );
  }
  if (stored.length < 8) {
    malformed("NDS BLZ input is too small to contain the 8-byte footer");
  }

  const footerOffset = stored.length - 8;
  const compressedLengthAndHeader = stored.readUInt32LE(footerOffset);
  const headerSize = compressedLengthAndHeader >>> 24;
  const compressedLength = compressedLengthAndHeader & 0x00ff_ffff;
  const extraSize = stored.readUInt32LE(footerOffset + 4);

  if (headerSize < 8 || headerSize > stored.length) {
    malformed(`NDS BLZ header size ${headerSize} is outside the stored input`);
  }
  if (compressedLength < headerSize || compressedLength > stored.length) {
    malformed(
      `NDS BLZ compressed length ${compressedLength} is incompatible with header size ${headerSize} and stored size ${stored.length}`,
    );
  }

  const encodedRegionSize = compressedLength - headerSize;
  if (encodedRegionSize < 1) {
    malformed("NDS BLZ encoded region is empty");
  }

  const paddingStart = stored.length - headerSize;
  for (let index = paddingStart; index < footerOffset; index += 1) {
    if (stored[index] !== 0xff) {
      malformed("NDS BLZ header padding must contain only 0xFF bytes");
    }
  }

  const decodedSizeFromFooter = stored.length + extraSize;
  if (!Number.isSafeInteger(decodedSizeFromFooter)) {
    malformed("NDS BLZ decoded size overflows the safe integer range");
  }
  if (decodedSizeFromFooter > limits.maxDecodedBytes) {
    outputLimit(
      `NDS BLZ footer expands to ${decodedSizeFromFooter} bytes, above the ${limits.maxDecodedBytes}-byte decoded limit`,
    );
  }
  if (decodedSizeFromFooter !== expectedDecodedSize) {
    throw new NdsError(
      "blz-output-size-mismatch",
      `NDS BLZ footer describes ${decodedSizeFromFooter} decoded bytes, expected ${expectedDecodedSize}`,
    );
  }

  const passthroughSize = stored.length - compressedLength;
  const decodedRegionSize = expectedDecodedSize - passthroughSize;
  if (decodedRegionSize < 1) {
    malformed("NDS BLZ decoded region is empty or precedes the uncompressed prefix");
  }

  const encodedStart = passthroughSize;
  const encodedEnd = paddingStart;
  if (encodedEnd - encodedStart !== decodedRegionSize) {
    malformed("NDS BLZ encoded-region geometry is inconsistent");
  }

  const output = Buffer.allocUnsafe(expectedDecodedSize);
  if (passthroughSize > 0) {
    stored.copy(output, 0, 0, passthroughSize);
  }

  let readIndex = encodedEnd - 1;
  let decodedCount = 0;

  while (decodedCount < decodedRegionSize) {
    if (readIndex < encodedStart) {
      malformed("NDS BLZ stream ended before the decoded region was complete");
    }
    const flags = stored[readIndex]!;
    readIndex -= 1;

    for (let mask = 0x80; mask !== 0 && decodedCount < decodedRegionSize; mask >>>= 1) {
      if ((flags & mask) === 0) {
        if (readIndex < encodedStart) {
          malformed("NDS BLZ literal token is truncated");
        }
        output[expectedDecodedSize - 1 - decodedCount] = stored[readIndex]!;
        readIndex -= 1;
        decodedCount += 1;
        continue;
      }

      if (readIndex - 1 < encodedStart) {
        malformed("NDS BLZ back-reference token is truncated");
      }
      const byte1 = stored[readIndex]!;
      const byte2 = stored[readIndex - 1]!;
      readIndex -= 2;

      const length = (byte1 >>> 4) + 3;
      const displacement = (((byte1 & 0x0f) << 8) | byte2) + 3;
      if (displacement > decodedCount) {
        malformed(
          `NDS BLZ back-reference displacement ${displacement} exceeds ${decodedCount} bytes of decoded history`,
        );
      }
      if (decodedCount + length > decodedRegionSize) {
        malformed("NDS BLZ back-reference writes beyond the expected decoded region");
      }

      let sourceDecodedIndex = decodedCount - displacement;
      for (let copied = 0; copied < length; copied += 1) {
        const sourceIndex = expectedDecodedSize - 1 - sourceDecodedIndex;
        const destinationIndex = expectedDecodedSize - 1 - decodedCount;
        if (
          sourceIndex < passthroughSize
          || sourceIndex >= expectedDecodedSize
          || destinationIndex < passthroughSize
          || destinationIndex >= expectedDecodedSize
        ) {
          malformed("NDS BLZ back-reference leaves the validated decoded range");
        }
        output[destinationIndex] = output[sourceIndex]!;
        sourceDecodedIndex += 1;
        decodedCount += 1;
      }
    }
  }

  return {
    bytes: output,
    storedSize: stored.length,
    decodedSize: output.length,
    headerSize,
    encodedRegionSize,
  };
}