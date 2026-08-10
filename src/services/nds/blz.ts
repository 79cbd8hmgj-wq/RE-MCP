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

export interface NdsBlzEncodeResult {
  readonly bytes: Buffer;
  readonly storedSize: number;
  readonly decodedSize: number;
  readonly headerSize: number;
  readonly encodedRegionSize: number;
  readonly passthroughSize: number;
}

const MAX_OVERLAY_BYTES = 16 * 1024 * 1024;
const MAX_BLZ_MATCH_LENGTH = 18;
const MIN_BLZ_DISPLACEMENT = 3;
const MAX_BLZ_DISPLACEMENT = 0x1002;
const MAX_BLZ_MATCH_CANDIDATES = 64;

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

function recompressionFailed(message: string): never {
  throw new NdsError("blz-recompression-failed", message);
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

interface BlzMatch {
  readonly length: number;
  readonly displacement: number;
}

interface BlzMatchBucket {
  positions: number[];
  head: number;
}

interface BlzMatchState {
  readonly buckets: Map<number, BlzMatchBucket>;
}

interface BlzEncodingChoice {
  readonly processedBytes: number;
  readonly encodedLength: number;
  readonly passthroughSize: number;
  readonly paddingSize: number;
  readonly headerSize: number;
  readonly compressedLength: number;
  readonly storedSize: number;
}

function logicalByte(decoded: Buffer, position: number): number {
  return decoded[decoded.length - 1 - position]!;
}

function matchKey(decoded: Buffer, position: number): number | null {
  if (position + 2 >= decoded.length) {
    return null;
  }
  return (
    (logicalByte(decoded, position) << 16)
    | (logicalByte(decoded, position + 1) << 8)
    | logicalByte(decoded, position + 2)
  );
}

function createMatchState(): BlzMatchState {
  return { buckets: new Map<number, BlzMatchBucket>() };
}

function evictExpiredPosition(
  decoded: Buffer,
  state: BlzMatchState,
  newestPosition: number,
): void {
  const expiredPosition = newestPosition - MAX_BLZ_DISPLACEMENT - 1;
  if (expiredPosition < 0) {
    return;
  }
  const key = matchKey(decoded, expiredPosition);
  if (key === null) {
    return;
  }
  const bucket = state.buckets.get(key);
  if (bucket === undefined) {
    return;
  }
  while (
    bucket.head < bucket.positions.length
    && bucket.positions[bucket.head]! <= expiredPosition
  ) {
    bucket.head += 1;
  }
  if (bucket.head === bucket.positions.length) {
    state.buckets.delete(key);
    return;
  }
  if (bucket.head > 64 && bucket.head * 2 > bucket.positions.length) {
    bucket.positions = bucket.positions.slice(bucket.head);
    bucket.head = 0;
  }
}

function addHistoryPosition(
  decoded: Buffer,
  state: BlzMatchState,
  position: number,
): void {
  evictExpiredPosition(decoded, state, position);
  const key = matchKey(decoded, position);
  if (key === null) {
    return;
  }
  let bucket = state.buckets.get(key);
  if (bucket === undefined) {
    bucket = { positions: [], head: 0 };
    state.buckets.set(key, bucket);
  }
  bucket.positions.push(position);
}

function addHistoryRange(
  decoded: Buffer,
  state: BlzMatchState,
  start: number,
  end: number,
): void {
  for (let position = start; position < end; position += 1) {
    addHistoryPosition(decoded, state, position);
  }
}

function findBestMatch(
  decoded: Buffer,
  state: BlzMatchState,
  position: number,
): BlzMatch {
  const key = matchKey(decoded, position);
  if (key === null) {
    return { length: 0, displacement: 0 };
  }
  const bucket = state.buckets.get(key);
  if (bucket === undefined) {
    return { length: 0, displacement: 0 };
  }

  let bestLength = 0;
  let bestDisplacement = 0;
  let inspectedCandidates = 0;

  for (let index = bucket.positions.length - 1; index >= bucket.head; index -= 1) {
    const candidatePosition = bucket.positions[index]!;
    const displacement = position - candidatePosition;
    if (displacement < MIN_BLZ_DISPLACEMENT) {
      continue;
    }
    if (displacement > MAX_BLZ_DISPLACEMENT) {
      break;
    }

    inspectedCandidates += 1;
    if (inspectedCandidates > MAX_BLZ_MATCH_CANDIDATES) {
      break;
    }

    const maxLength = Math.min(
      MAX_BLZ_MATCH_LENGTH,
      decoded.length - position,
    );
    let length = 0;
    while (
      length < maxLength
      && logicalByte(decoded, candidatePosition + length)
        === logicalByte(decoded, position + length)
    ) {
      length += 1;
    }

    if (
      length >= 3
      && (
        length > bestLength
        || (
          length === bestLength
          && (bestDisplacement === 0 || displacement < bestDisplacement)
        )
      )
    ) {
      bestLength = length;
      bestDisplacement = displacement;
      if (bestLength === MAX_BLZ_MATCH_LENGTH) {
        break;
      }
    }
  }

  return { length: bestLength, displacement: bestDisplacement };
}

function paddingForFourByteAlignment(prefixSize: number, encodedLength: number): number {
  return (4 - ((prefixSize + encodedLength) % 4)) % 4;
}

function chooseEncoding(decoded: Buffer): BlzEncodingChoice | null {
  const state = createMatchState();
  let position = 0;
  let tokenIndex = 0;
  let encodedLength = 0;
  let best: BlzEncodingChoice | null = null;

  while (position < decoded.length) {
    const match = findBestMatch(decoded, state, position);
    const tokenLength = match.length >= 3 ? match.length : 1;
    const tokenBytes = match.length >= 3 ? 2 : 1;

    if (tokenIndex === 0) {
      encodedLength += 1;
    }
    encodedLength += tokenBytes;

    const previousPosition = position;
    position += tokenLength;
    addHistoryRange(decoded, state, previousPosition, position);
    tokenIndex = (tokenIndex + 1) % 8;

    const passthroughSize = decoded.length - position;
    const paddingSize = paddingForFourByteAlignment(
      passthroughSize,
      encodedLength,
    );
    const headerSize = 8 + paddingSize;
    const compressedLength = encodedLength + headerSize;
    const storedSize = passthroughSize + compressedLength;

    if (
      storedSize < decoded.length
      && (best === null || storedSize < best.storedSize)
    ) {
      best = {
        processedBytes: position,
        encodedLength,
        passthroughSize,
        paddingSize,
        headerSize,
        compressedLength,
        storedSize,
      };
    }
  }

  return best;
}

function emitEncodedRegion(
  decoded: Buffer,
  choice: BlzEncodingChoice,
): Buffer {
  const encoded = Buffer.allocUnsafe(choice.encodedLength);
  const state = createMatchState();
  let position = 0;
  let writeOffset = 0;

  while (position < choice.processedBytes) {
    const flagsOffset = writeOffset;
    writeOffset += 1;
    let flags = 0;

    for (
      let tokenIndex = 0;
      tokenIndex < 8 && position < choice.processedBytes;
      tokenIndex += 1
    ) {
      const match = findBestMatch(decoded, state, position);
      const canUseMatch = (
        match.length >= 3
        && position + match.length <= choice.processedBytes
      );
      const tokenLength = canUseMatch ? match.length : 1;
      const previousPosition = position;

      if (!canUseMatch) {
        encoded[writeOffset] = logicalByte(decoded, position);
        writeOffset += 1;
      } else {
        flags |= 0x80 >>> tokenIndex;
        const encodedDisplacement = match.displacement - MIN_BLZ_DISPLACEMENT;
        encoded[writeOffset] = (
          ((match.length - 3) << 4)
          | ((encodedDisplacement >>> 8) & 0x0f)
        );
        encoded[writeOffset + 1] = encodedDisplacement & 0xff;
        writeOffset += 2;
      }

      position += tokenLength;
      addHistoryRange(decoded, state, previousPosition, position);
    }

    encoded[flagsOffset] = flags;
  }

  if (writeOffset !== choice.encodedLength) {
    recompressionFailed(
      `NDS BLZ deterministic encoder emitted ${writeOffset} bytes, expected ${choice.encodedLength}`,
    );
  }

  encoded.reverse();
  return encoded;
}

export function encodeNdsBlz(
  decoded: Buffer,
  limits: NdsBlzLimits = DEFAULT_NDS_BLZ_LIMITS,
): NdsBlzEncodeResult {
  validatePositiveLimit(limits.maxStoredBytes, "maxStoredBytes");
  validatePositiveLimit(limits.maxDecodedBytes, "maxDecodedBytes");

  if (decoded.length < 1) {
    recompressionFailed("NDS BLZ decoded input must contain at least one byte");
  }
  if (decoded.length > limits.maxDecodedBytes) {
    outputLimit(
      `NDS BLZ decoded input is ${decoded.length} bytes, above the ${limits.maxDecodedBytes}-byte decoded limit`,
    );
  }

  const choice = chooseEncoding(decoded);
  if (choice === null) {
    recompressionFailed(
      "NDS BLZ decoded input has no canonical compressed representation smaller than the decoded bytes",
    );
  }
  if (choice.storedSize > limits.maxStoredBytes) {
    outputLimit(
      `NDS BLZ recompressed output would be ${choice.storedSize} bytes, above the ${limits.maxStoredBytes}-byte stored limit`,
    );
  }
  if (choice.compressedLength > 0x00ff_ffff) {
    recompressionFailed(
      "NDS BLZ compressed region cannot be represented by the 24-bit footer length",
    );
  }

  const encoded = emitEncodedRegion(decoded, choice);
  const padding = Buffer.alloc(choice.paddingSize, 0xff);
  const footer = Buffer.alloc(8);
  const compressedLengthAndHeader = (
    choice.headerSize * 0x0100_0000
    + choice.compressedLength
  );
  footer.writeUInt32LE(compressedLengthAndHeader, 0);
  footer.writeUInt32LE(decoded.length - choice.storedSize, 4);

  const bytes = Buffer.concat(
    [
      decoded.subarray(0, choice.passthroughSize),
      encoded,
      padding,
      footer,
    ],
    choice.storedSize,
  );

  return {
    bytes,
    storedSize: bytes.length,
    decodedSize: decoded.length,
    headerSize: choice.headerSize,
    encodedRegionSize: encoded.length,
    passthroughSize: choice.passthroughSize,
  };
}
