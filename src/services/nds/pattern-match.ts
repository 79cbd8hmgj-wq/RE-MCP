import { NdsError } from "./errors.js";
import { patternSpanIsEligible, type ResolvedNdsPatternScope } from "./pattern-scope.js";
import type { CompiledNdsPattern } from "./patterns.js";

export type NdsPatternTruncationReason =
  | "scan-byte-limit"
  | "match-count-limit";

export interface NdsPatternMatchOptions {
  readonly offset: number;
  readonly limit: number;
  readonly maxScanBytes: number;
}

export interface NdsPatternScanResult {
  readonly status: "complete" | "truncated";
  readonly truncationReasons: readonly NdsPatternTruncationReason[];
  readonly offset: number;
  readonly limit: number;
  readonly nextOffset: number | null;
  readonly scannedBytes: number;
  readonly discoveredMatches: number;
  readonly matchOffsets: readonly number[];
}

export type NdsPatternReadAt = (
  romOffset: number,
  length: number,
) => Promise<Buffer>;

export const NDS_PATTERN_DEFAULT_SCAN_BYTES = 64 * 1024 * 1024;
export const NDS_PATTERN_MAX_SCAN_BYTES = 512 * 1024 * 1024;
export const NDS_PATTERN_DEFAULT_LIMIT = 100;
export const NDS_PATTERN_MAX_LIMIT = 1000;
export const NDS_PATTERN_MAX_OFFSET = 99999;
export const NDS_PATTERN_MATCH_CEILING = 100000;
export const NDS_PATTERN_SCAN_CHUNK_BYTES = 64 * 1024;

function limitError(message: string): never {
  throw new NdsError("pattern-search-limit-exceeded", message);
}

function requireSafeIntegerInRange(
  value: number,
  minimum: number,
  maximum: number,
  label: string,
): void {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    limitError(`${label} must be a safe integer between ${minimum} and ${maximum}`);
  }
}

function validateOptions(
  options: NdsPatternMatchOptions,
  internalChunkBytes: number,
): void {
  requireSafeIntegerInRange(options.offset, 0, NDS_PATTERN_MAX_OFFSET, "Pattern match offset");
  requireSafeIntegerInRange(options.limit, 1, NDS_PATTERN_MAX_LIMIT, "Pattern match limit");
  requireSafeIntegerInRange(
    options.maxScanBytes,
    1,
    NDS_PATTERN_MAX_SCAN_BYTES,
    "Pattern scan byte limit",
  );
  if (!Number.isSafeInteger(internalChunkBytes) || internalChunkBytes < 1) {
    limitError("Internal pattern scan chunk size must be a positive safe integer");
  }
}

function matchesAt(
  window: Buffer,
  relativeStart: number,
  pattern: CompiledNdsPattern,
): boolean {
  for (let index = 0; index < pattern.bytes.length; index += 1) {
    const actual = window[relativeStart + index];
    const expected = pattern.bytes[index];
    const mask = pattern.mask[index];
    if (actual === undefined || expected === undefined || mask === undefined) {
      return false;
    }
    if ((actual & mask) !== (expected & mask)) {
      return false;
    }
  }
  return true;
}

function totalPhysicalBytes(scope: ResolvedNdsPatternScope): number {
  let total = 0;
  for (const range of scope.physicalRanges) {
    if (range.end > range.start) total += range.end - range.start;
  }
  return total;
}

export async function scanNdsPatternMatches(
  scope: ResolvedNdsPatternScope,
  pattern: CompiledNdsPattern,
  readAt: NdsPatternReadAt,
  options: NdsPatternMatchOptions,
  internalChunkBytes = NDS_PATTERN_SCAN_CHUNK_BYTES,
): Promise<NdsPatternScanResult> {
  validateOptions(options, internalChunkBytes);
  if (pattern.bytes.length < 1 || pattern.bytes.length !== pattern.mask.length) {
    throw new NdsError("invalid-pattern", "Compiled pattern bytes and mask must be non-empty and equal length");
  }

  const ranges = [...scope.physicalRanges]
    .filter((range) => range.end > range.start)
    .sort((left, right) => left.start - right.start || left.end - right.end);
  const physicalBytes = totalPhysicalBytes({ ...scope, physicalRanges: ranges });
  const pageEnd = options.offset + options.limit;
  const matchOffsets: number[] = [];
  let discoveredMatches = 0;
  let scannedBytes = 0;
  let matchLimitReached = false;

  outer:
  for (const range of ranges) {
    let position = range.start;
    let carry = Buffer.alloc(0);
    let nextCandidateStart = range.start;

    while (position < range.end) {
      const remainingBudget = options.maxScanBytes - scannedBytes;
      if (remainingBudget <= 0) break outer;

      const readLength = Math.min(
        internalChunkBytes,
        range.end - position,
        remainingBudget,
      );
      const freshStart = position;
      const fresh = await readAt(freshStart, readLength);
      if (fresh.length !== readLength) {
        throw new NdsError(
          "range-out-of-bounds",
          `NDS pattern reader returned ${fresh.length} bytes for a ${readLength}-byte request`,
        );
      }

      const windowStart = freshStart - carry.length;
      const window = carry.length === 0
        ? fresh
        : Buffer.concat([carry, fresh]);
      const freshEnd = freshStart + fresh.length;
      scannedBytes += fresh.length;
      position = freshEnd;

      const maximumCandidateStart = freshEnd - pattern.bytes.length;
      let candidateStart = Math.max(nextCandidateStart, windowStart);
      for (; candidateStart <= maximumCandidateStart; candidateStart += 1) {
        const candidateEnd = candidateStart + pattern.bytes.length;
        if (candidateStart % pattern.alignment !== 0) continue;
        if (!patternSpanIsEligible(scope, candidateStart, candidateEnd)) continue;
        const relativeStart = candidateStart - windowStart;
        if (!matchesAt(window, relativeStart, pattern)) continue;

        const matchIndex = discoveredMatches;
        discoveredMatches += 1;
        if (matchIndex >= options.offset && matchIndex < pageEnd) {
          matchOffsets.push(candidateStart);
        }
        if (discoveredMatches >= NDS_PATTERN_MATCH_CEILING) {
          matchLimitReached = true;
          break outer;
        }
      }

      if (maximumCandidateStart >= nextCandidateStart) {
        nextCandidateStart = maximumCandidateStart + 1;
      }
      const carryLength = Math.min(pattern.bytes.length - 1, window.length);
      carry = carryLength === 0
        ? Buffer.alloc(0)
        : Buffer.from(window.subarray(window.length - carryLength));
    }
  }

  const scanLimitReached = scannedBytes < physicalBytes
    && scannedBytes >= options.maxScanBytes;
  const truncationReasons: NdsPatternTruncationReason[] = [];
  if (scanLimitReached) truncationReasons.push("scan-byte-limit");
  if (matchLimitReached) truncationReasons.push("match-count-limit");

  const returnedEndIndex = options.offset + matchOffsets.length;
  const nextOffset = returnedEndIndex < discoveredMatches
    ? returnedEndIndex
    : null;

  return {
    status: truncationReasons.length === 0 ? "complete" : "truncated",
    truncationReasons,
    offset: options.offset,
    limit: options.limit,
    nextOffset,
    scannedBytes,
    discoveredMatches,
    matchOffsets,
  };
}
