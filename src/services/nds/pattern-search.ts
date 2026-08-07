import { open } from "node:fs/promises";

import { NdsError } from "./errors.js";
import { hashFileSha256, readExact } from "./io.js";
import {
  NDS_PATTERN_DEFAULT_LIMIT,
  NDS_PATTERN_DEFAULT_SCAN_BYTES,
  scanNdsPatternMatches,
  type NdsPatternTruncationReason,
} from "./pattern-match.js";
import {
  ownersForNdsPatternHit,
  type NdsPatternOwner,
} from "./pattern-ownership.js";
import {
  resolveNdsPatternScope,
  selectPatternContextComponent,
  type NdsPatternSearchScope,
  type ResolvedNdsPatternScope,
} from "./pattern-scope.js";
import {
  compileNdsPattern,
  type CompiledNdsPattern,
  type NdsSearchPattern,
} from "./patterns.js";
import type { NdsRomMap } from "./rom-map.js";

export interface NdsPatternHitContext {
  readonly beforeHex: string;
  readonly afterHex: string;
  readonly clippedAtStart: boolean;
  readonly clippedAtEnd: boolean;
}

export interface NdsPatternHit {
  readonly romOffset: number;
  readonly endOffset: number;
  readonly length: number;
  readonly bytesHex: string;
  readonly owners: readonly NdsPatternOwner[];
  readonly context?: NdsPatternHitContext;
}

export interface NdsPatternSearchOptions {
  readonly offset?: number;
  readonly limit?: number;
  readonly maxScanBytes?: number;
  readonly contextBytes?: number;
}

export interface NdsPatternSearchResult {
  readonly status: "complete" | "truncated";
  readonly truncationReasons: readonly NdsPatternTruncationReason[];
  readonly offset: number;
  readonly limit: number;
  readonly nextOffset: number | null;
  readonly scannedBytes: number;
  readonly discoveredMatches: number;
  readonly matches: readonly NdsPatternHit[];
}

export const NDS_PATTERN_MAX_CONTEXT_BYTES = 64;

export interface NdsPatternSearchDependencies {
  readonly hashFileSha256: (filePath: string) => Promise<string>;
}

function requireContextBytes(value: number): void {
  if (
    !Number.isSafeInteger(value)
    || value < 0
    || value > NDS_PATTERN_MAX_CONTEXT_BYTES
  ) {
    throw new NdsError(
      "pattern-search-limit-exceeded",
      `Pattern context bytes must be a safe integer between 0 and ${NDS_PATTERN_MAX_CONTEXT_BYTES}`,
    );
  }
}

async function readContext(
  scope: ResolvedNdsPatternScope,
  map: NdsRomMap,
  readAt: (offset: number, length: number, label: string) => Promise<Buffer>,
  hitStart: number,
  hitEnd: number,
  contextBytes: number,
): Promise<NdsPatternHitContext> {
  let lowerBound = 0;
  let upperBound = map.fileSize;

  if (scope.kind === "components") {
    const component = selectPatternContextComponent(scope, hitStart, hitEnd);
    if (component === null) {
      throw new NdsError(
        "invalid-pattern-scope",
        "Pattern hit does not have a selected containing component for context",
      );
    }
    lowerBound = component.start;
    upperBound = component.end;
  }

  const requestedBeforeStart = hitStart - contextBytes;
  const requestedAfterEnd = hitEnd + contextBytes;
  const beforeStart = Math.max(lowerBound, requestedBeforeStart);
  const afterEnd = Math.min(upperBound, requestedAfterEnd);
  const beforeLength = hitStart - beforeStart;
  const afterLength = afterEnd - hitEnd;

  const before = beforeLength === 0
    ? Buffer.alloc(0)
    : await readAt(beforeStart, beforeLength, "NDS pattern context before hit");
  const after = afterLength === 0
    ? Buffer.alloc(0)
    : await readAt(hitEnd, afterLength, "NDS pattern context after hit");

  return {
    beforeHex: before.toString("hex"),
    afterHex: after.toString("hex"),
    clippedAtStart: beforeStart !== requestedBeforeStart,
    clippedAtEnd: afterEnd !== requestedAfterEnd,
  };
}

async function buildHit(
  map: NdsRomMap,
  scope: ResolvedNdsPatternScope,
  pattern: CompiledNdsPattern,
  readAt: (offset: number, length: number, label: string) => Promise<Buffer>,
  romOffset: number,
  contextBytes: number,
): Promise<NdsPatternHit> {
  const endOffset = romOffset + pattern.bytes.length;
  const matched = await readAt(
    romOffset,
    pattern.bytes.length,
    "NDS pattern hit",
  );
  const base = {
    romOffset,
    endOffset,
    length: pattern.bytes.length,
    bytesHex: matched.toString("hex"),
    owners: ownersForNdsPatternHit(map, romOffset, endOffset),
  };
  if (contextBytes === 0) {
    return base;
  }
  return {
    ...base,
    context: await readContext(
      scope,
      map,
      readAt,
      romOffset,
      endOffset,
      contextBytes,
    ),
  };
}

export async function searchNdsPattern(
  map: NdsRomMap,
  patternRequest: NdsSearchPattern,
  scopeRequest: NdsPatternSearchScope,
  options: NdsPatternSearchOptions = {},
  dependencies: Partial<NdsPatternSearchDependencies> = {},
): Promise<NdsPatternSearchResult> {
  const hash = dependencies.hashFileSha256 ?? hashFileSha256;
  const offset = options.offset ?? 0;
  const limit = options.limit ?? NDS_PATTERN_DEFAULT_LIMIT;
  const maxScanBytes = options.maxScanBytes ?? NDS_PATTERN_DEFAULT_SCAN_BYTES;
  const contextBytes = options.contextBytes ?? 0;
  requireContextBytes(contextBytes);

  const pattern = compileNdsPattern(patternRequest);
  const scope = resolveNdsPatternScope(map, scopeRequest);

  if (await hash(map.romPath) !== map.sha256) {
    throw new NdsError(
      "invalid-rom",
      "Source ROM no longer matches the canonical map identity",
    );
  }

  const handle = await open(map.romPath, "r");
  let outcome:
    | { readonly ok: true; readonly value: NdsPatternSearchResult }
    | { readonly ok: false; readonly error: unknown };

  try {
    const readAt = async (
      romOffset: number,
      length: number,
      label = "NDS pattern search",
    ): Promise<Buffer> => await readExact(handle, romOffset, length, label);

    const scan = await scanNdsPatternMatches(
      scope,
      pattern,
      async (romOffset, length) => await readAt(romOffset, length),
      { offset, limit, maxScanBytes },
    );
    const matches: NdsPatternHit[] = [];
    for (const romOffset of scan.matchOffsets) {
      matches.push(await buildHit(
        map,
        scope,
        pattern,
        readAt,
        romOffset,
        contextBytes,
      ));
    }

    outcome = {
      ok: true,
      value: {
        status: scan.status,
        truncationReasons: scan.truncationReasons,
        offset: scan.offset,
        limit: scan.limit,
        nextOffset: scan.nextOffset,
        scannedBytes: scan.scannedBytes,
        discoveredMatches: scan.discoveredMatches,
        matches,
      },
    };
  } catch (error) {
    outcome = { ok: false, error };
  } finally {
    await handle.close();
  }

  if (await hash(map.romPath) !== map.sha256) {
    throw new NdsError(
      "invalid-rom",
      "Source ROM changed during pattern search",
    );
  }
  if (!outcome.ok) {
    throw outcome.error;
  }
  return outcome.value;
}
