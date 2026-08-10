import { createHash } from "node:crypto";

import {
  DEFAULT_NDS_BLZ_LIMITS,
  decodeNdsBlz,
  type NdsBlzLimits,
} from "./blz.js";
import { NdsError } from "./errors.js";

export const NDS_BLZ_ENCODER_CONTRACT_VERSION = 1 as const;

export interface NdsBlzEncodeResult {
  readonly bytes: Buffer;
  readonly storedSize: number;
  readonly runtimeSize: number;
  readonly storedSha256: string;
  readonly runtimeSha256: string;
  readonly contractVersion: 1;
}

const MIN_MATCH_LENGTH = 3;
const MAX_MATCH_LENGTH = 18;
const MIN_DISPLACEMENT = 3;
const MAX_DISPLACEMENT = 4098;
const MAX_PACKED_COMPRESSED_LENGTH = 0x00ff_ffff;

interface Match {
  readonly length: number;
  readonly displacement: number;
}

interface MatchBucket {
  positions: number[];
  head: number;
}

interface MatchState {
  readonly buckets: Map<number, MatchBucket>;
}

interface EncodingChoice {
  readonly processedBytes: number;
  readonly encodedLength: number;
  readonly passthroughSize: number;
  readonly paddingSize: number;
  readonly headerSize: number;
  readonly compressedLength: number;
  readonly storedSize: number;
}

function sha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function encodeFailed(message: string): never {
  throw new NdsError("blz-encode-failed", message);
}

function outputLimit(message: string): never {
  throw new NdsError("blz-output-limit", message);
}

function roundTripMismatch(message: string): never {
  throw new NdsError("blz-roundtrip-mismatch", message);
}

function validatePositiveLimit(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value < 1) {
    outputLimit(`${label} must be a positive safe integer`);
  }
}

function logicalByte(runtime: Buffer, position: number): number {
  return runtime[runtime.length - 1 - position]!;
}

function matchKey(runtime: Buffer, position: number): number | null {
  if (position + 2 >= runtime.length) {
    return null;
  }
  return (
    (logicalByte(runtime, position) << 16)
    | (logicalByte(runtime, position + 1) << 8)
    | logicalByte(runtime, position + 2)
  );
}

function createMatchState(): MatchState {
  return { buckets: new Map<number, MatchBucket>() };
}

function pruneBucket(
  runtime: Buffer,
  state: MatchState,
  newestPosition: number,
): void {
  const oldestAllowed = newestPosition - MAX_DISPLACEMENT;
  if (oldestAllowed <= 0) {
    return;
  }
  const expiredPosition = oldestAllowed - 1;
  const key = matchKey(runtime, expiredPosition);
  if (key === null) {
    return;
  }
  const bucket = state.buckets.get(key);
  if (bucket === undefined) {
    return;
  }
  while (
    bucket.head < bucket.positions.length
    && bucket.positions[bucket.head]! < oldestAllowed
  ) {
    bucket.head += 1;
  }
  if (bucket.head === bucket.positions.length) {
    state.buckets.delete(key);
    return;
  }
  if (bucket.head > 1024 && bucket.head * 2 > bucket.positions.length) {
    bucket.positions = bucket.positions.slice(bucket.head);
    bucket.head = 0;
  }
}

function addHistoryPosition(
  runtime: Buffer,
  state: MatchState,
  position: number,
): void {
  pruneBucket(runtime, state, position);
  const key = matchKey(runtime, position);
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
  runtime: Buffer,
  state: MatchState,
  start: number,
  end: number,
): void {
  for (let position = start; position < end; position += 1) {
    addHistoryPosition(runtime, state, position);
  }
}

function findBestMatch(
  runtime: Buffer,
  state: MatchState,
  position: number,
): Match {
  const key = matchKey(runtime, position);
  if (key === null) {
    return { length: 0, displacement: 0 };
  }
  const bucket = state.buckets.get(key);
  if (bucket === undefined) {
    return { length: 0, displacement: 0 };
  }

  let bestLength = 0;
  let bestDisplacement = 0;
  const maximumLength = Math.min(MAX_MATCH_LENGTH, runtime.length - position);

  for (let index = bucket.positions.length - 1; index >= bucket.head; index -= 1) {
    const candidatePosition = bucket.positions[index]!;
    const displacement = position - candidatePosition;
    if (displacement < MIN_DISPLACEMENT) {
      continue;
    }
    if (displacement > MAX_DISPLACEMENT) {
      break;
    }

    let length = 0;
    while (
      length < maximumLength
      && logicalByte(runtime, candidatePosition + length)
        === logicalByte(runtime, position + length)
    ) {
      length += 1;
    }

    if (length < MIN_MATCH_LENGTH) {
      continue;
    }
    if (length > bestLength) {
      bestLength = length;
      bestDisplacement = displacement;
    } else if (length === bestLength && displacement < bestDisplacement) {
      bestDisplacement = displacement;
    }

    if (bestLength === maximumLength) {
      break;
    }
  }

  return { length: bestLength, displacement: bestDisplacement };
}

function paddingForAlignment(prefixSize: number, encodedLength: number): number {
  return (4 - ((prefixSize + encodedLength) % 4)) % 4;
}

function chooseEncoding(runtime: Buffer): EncodingChoice | null {
  const state = createMatchState();
  let position = 0;
  let encodedLength = 0;
  let best: EncodingChoice | null = null;

  while (position < runtime.length) {
    let tokenCount = 0;
    encodedLength += 1;

    while (tokenCount < 8 && position < runtime.length) {
      const match = findBestMatch(runtime, state, position);
      const previousPosition = position;
      if (match.length >= MIN_MATCH_LENGTH) {
        encodedLength += 2;
        position += match.length;
      } else {
        encodedLength += 1;
        position += 1;
      }
      addHistoryRange(runtime, state, previousPosition, position);
      tokenCount += 1;
    }

    const passthroughSize = runtime.length - position;
    const paddingSize = paddingForAlignment(passthroughSize, encodedLength);
    const headerSize = 8 + paddingSize;
    const compressedLength = encodedLength + headerSize;
    const storedSize = passthroughSize + compressedLength;

    if (
      storedSize < runtime.length
      && compressedLength <= MAX_PACKED_COMPRESSED_LENGTH
      && (
        best === null
        || storedSize < best.storedSize
        || (storedSize === best.storedSize && passthroughSize < best.passthroughSize)
      )
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

function emitEncodedSuffix(runtime: Buffer, choice: EncodingChoice): Buffer {
  const output = Buffer.allocUnsafe(choice.encodedLength);
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
      const match = findBestMatch(runtime, state, position);
      const canUseMatch = (
        match.length >= MIN_MATCH_LENGTH
        && position + match.length <= choice.processedBytes
      );
      const previousPosition = position;

      if (!canUseMatch) {
        output[writeOffset] = logicalByte(runtime, position);
        writeOffset += 1;
        position += 1;
      } else {
        flags |= 0x80 >>> tokenIndex;
        const packedDisplacement = match.displacement - MIN_DISPLACEMENT;
        output[writeOffset] = (
          ((match.length - MIN_MATCH_LENGTH) << 4)
          | ((packedDisplacement >>> 8) & 0x0f)
        );
        output[writeOffset + 1] = packedDisplacement & 0xff;
        writeOffset += 2;
        position += match.length;
      }

      addHistoryRange(runtime, state, previousPosition, position);
    }

    output[flagsOffset] = flags;
  }

  if (writeOffset !== output.length) {
    encodeFailed(
      `Deterministic NDS BLZ emission produced ${writeOffset} bytes, expected ${output.length}`,
    );
  }

  output.reverse();
  return output;
}

export function encodeNdsBlz(
  runtime: Buffer,
  limits: NdsBlzLimits = DEFAULT_NDS_BLZ_LIMITS,
): NdsBlzEncodeResult {
  validatePositiveLimit(limits.maxStoredBytes, "maxStoredBytes");
  validatePositiveLimit(limits.maxDecodedBytes, "maxDecodedBytes");

  if (runtime.length === 0) {
    encodeFailed("NDS BLZ runtime input must not be empty");
  }
  if (runtime.length > limits.maxDecodedBytes) {
    outputLimit(
      `NDS BLZ runtime input is ${runtime.length} bytes, above the ${limits.maxDecodedBytes}-byte decoded limit`,
    );
  }

  const choice = chooseEncoding(runtime);
  if (choice === null) {
    encodeFailed(
      "No nonempty NDS BLZ encoded suffix produces a smaller representable stored image",
    );
  }
  if (choice.storedSize > limits.maxStoredBytes) {
    outputLimit(
      `NDS BLZ encoded output would be ${choice.storedSize} bytes, above the ${limits.maxStoredBytes}-byte stored limit`,
    );
  }

  const encodedSuffix = emitEncodedSuffix(runtime, choice);
  const footer = Buffer.alloc(8);
  const compressedLengthAndHeader = (
    choice.compressedLength
    | (choice.headerSize << 24)
  ) >>> 0;
  footer.writeUInt32LE(compressedLengthAndHeader, 0);
  footer.writeUInt32LE(runtime.length - choice.storedSize, 4);

  const bytes = Buffer.concat(
    [
      runtime.subarray(0, choice.passthroughSize),
      encodedSuffix,
      Buffer.alloc(choice.paddingSize, 0xff),
      footer,
    ],
    choice.storedSize,
  );

  let decoded: Buffer;
  try {
    decoded = decodeNdsBlz(bytes, runtime.length, limits).bytes;
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    roundTripMismatch(`Encoded NDS BLZ output failed canonical decode-back: ${detail}`);
  }
  if (!decoded.equals(runtime)) {
    roundTripMismatch("Encoded overlay did not decode to the requested runtime bytes");
  }

  return {
    bytes,
    storedSize: bytes.length,
    runtimeSize: runtime.length,
    storedSha256: sha256(bytes),
    runtimeSha256: sha256(runtime),
    contractVersion: NDS_BLZ_ENCODER_CONTRACT_VERSION,
  };
}