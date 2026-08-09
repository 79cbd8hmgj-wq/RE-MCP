import { open } from "node:fs/promises";

import type { ArmMode } from "../disassembly/backend.js";
import { NdsError } from "./errors.js";
import { hashFileSha256, readExact } from "./io.js";
import { createNdsOverlayRuntimeContext } from "./overlay-runtime.js";
import type { NdsOverlay, NdsProcessor } from "./overlays.js";
import {
  resolveRomOffset,
  resolveRuntimeAddress,
  type RomOffsetMatch,
  type RuntimeCandidate,
} from "./resolver.js";
import type { NdsRomMap } from "./rom-map.js";

const UINT32_MAX = 0xffffffff;

export type NdsDisassemblyMode = ArmMode | "auto";
export type NdsCodeRepresentation = "rom-file-backed" | "derived-overlay";

export interface NdsDisassemblyLocation {
  readonly processor: NdsProcessor;
  readonly mode: NdsDisassemblyMode;
  readonly runtimeAddress?: number;
  readonly romOffset?: number;
  readonly overlayId?: number;
}

export interface NdsCodeSourceCandidate {
  readonly processor: NdsProcessor;
  readonly component: "main" | "overlay";
  readonly overlayId: number | null;
  readonly runtimeAddress: number | null;
  readonly romOffset: number | null;
  readonly runtimeImageOffset: number | null;
  readonly runtimeStart: number;
  readonly runtimeEnd: number;
  readonly romStart: number | null;
  readonly romEnd: number | null;
  readonly representation: NdsCodeRepresentation | "runtime-only";
  readonly compressed: boolean;
  readonly bss: boolean;
}

export interface NdsCodeSource {
  readonly processor: NdsProcessor;
  readonly component: "main" | "overlay";
  readonly overlayId: number | null;
  readonly runtimeAddress: number;
  readonly romOffset: number | null;
  readonly runtimeImageOffset: number;
  readonly runtimeStart: number;
  readonly runtimeEnd: number;
  readonly romStart: number | null;
  readonly romEnd: number | null;
  readonly representation: NdsCodeRepresentation;
  readonly mode: ArmMode;
}

export type NdsCodeRead = (
  source: NdsCodeSource,
  maxBytes: number,
) => Promise<Buffer>;

export type NdsCodeSourceResolution =
  | { readonly status: "resolved"; readonly source: NdsCodeSource }
  | {
      readonly status: "ambiguous-code-source";
      readonly candidates: readonly NdsCodeSourceCandidate[];
    }
  | {
      readonly status: "compressed-overlay-not-decodable";
      readonly candidate: NdsCodeSourceCandidate;
    }
  | {
      readonly status: "runtime-only-bss";
      readonly candidate: NdsCodeSourceCandidate;
    }
  | {
      readonly status: "unmapped-address";
      readonly address: number;
      readonly processor: NdsProcessor;
    }
  | {
      readonly status: "mode-ambiguous";
      readonly address: number;
      readonly processor: NdsProcessor;
    };

function requireUint32(value: number, label: string): void {
  if (!Number.isInteger(value) || value < 0 || value > UINT32_MAX) {
    throw new NdsError(
      "range-out-of-bounds",
      `${label} must be a 32-bit unsigned integer`,
    );
  }
}

function requireOneLocation(
  location: NdsDisassemblyLocation,
): "runtime" | "rom" {
  const hasRuntime = location.runtimeAddress !== undefined;
  const hasRom = location.romOffset !== undefined;
  if (hasRuntime === hasRom) {
    throw new NdsError(
      "range-out-of-bounds",
      "Disassembly requires exactly one of runtimeAddress or romOffset",
    );
  }
  return hasRuntime ? "runtime" : "rom";
}

function overlaysFor(
  map: NdsRomMap,
  processor: NdsProcessor,
): readonly NdsOverlay[] {
  return processor === "arm9" ? map.overlays.arm9 : map.overlays.arm7;
}

function findOverlay(
  map: NdsRomMap,
  processor: NdsProcessor,
  overlayId: number,
): NdsOverlay | null {
  return overlaysFor(map, processor).find(
    (overlay) => overlay.overlayId === overlayId,
  ) ?? null;
}

function mainCandidate(
  map: NdsRomMap,
  processor: NdsProcessor,
  runtimeAddress: number,
  romOffset: number,
): NdsCodeSourceCandidate {
  const executable = processor === "arm9" ? map.header.arm9 : map.header.arm7;
  return {
    processor,
    component: "main",
    overlayId: null,
    runtimeAddress,
    romOffset,
    runtimeImageOffset: runtimeAddress - executable.ramAddress,
    runtimeStart: executable.ramAddress,
    runtimeEnd: executable.ramEnd,
    romStart: executable.romOffset,
    romEnd: executable.romEnd,
    representation: "rom-file-backed",
    compressed: false,
    bss: false,
  };
}

function overlayCandidate(
  overlay: NdsOverlay,
  runtimeAddress: number | null,
  romOffset: number | null,
  bss: boolean,
): NdsCodeSourceCandidate {
  const fileBackedSize = Math.min(overlay.ramSize, overlay.romSize);
  const relativeOffset = runtimeAddress === null
    ? null
    : runtimeAddress - overlay.ramAddress;

  if (bss) {
    return {
      processor: overlay.processor,
      component: "overlay",
      overlayId: overlay.overlayId,
      runtimeAddress,
      romOffset: null,
      runtimeImageOffset: null,
      runtimeStart: overlay.ramEnd,
      runtimeEnd: overlay.bssEnd,
      romStart: null,
      romEnd: null,
      representation: "runtime-only",
      compressed: overlay.compressed,
      bss: true,
    };
  }

  if (overlay.compressed) {
    return {
      processor: overlay.processor,
      component: "overlay",
      overlayId: overlay.overlayId,
      runtimeAddress,
      romOffset: null,
      runtimeImageOffset: relativeOffset,
      runtimeStart: overlay.ramAddress,
      runtimeEnd: overlay.ramEnd,
      romStart: null,
      romEnd: null,
      representation: "derived-overlay",
      compressed: true,
      bss: false,
    };
  }

  return {
    processor: overlay.processor,
    component: "overlay",
    overlayId: overlay.overlayId,
    runtimeAddress,
    romOffset,
    runtimeImageOffset: relativeOffset,
    runtimeStart: overlay.ramAddress,
    runtimeEnd: overlay.ramAddress + fileBackedSize,
    romStart: overlay.romOffset,
    romEnd: overlay.romOffset + fileBackedSize,
    representation: romOffset === null ? "runtime-only" : "rom-file-backed",
    compressed: false,
    bss: false,
  };
}

function fromRuntimeCandidate(
  map: NdsRomMap,
  candidate: RuntimeCandidate,
): NdsCodeSourceCandidate {
  if (candidate.kind === "arm9-main" || candidate.kind === "arm7-main") {
    if (candidate.romOffset === null) {
      throw new NdsError(
        "range-out-of-bounds",
        "Main executable candidate unexpectedly lacks a ROM offset",
      );
    }
    return mainCandidate(
      map,
      candidate.processor,
      candidate.runtimeAddress,
      candidate.romOffset,
    );
  }

  if (candidate.overlayId === null) {
    throw new NdsError(
      "range-out-of-bounds",
      "Overlay candidate unexpectedly lacks an overlay ID",
    );
  }
  const overlay = findOverlay(map, candidate.processor, candidate.overlayId);
  if (overlay === null) {
    throw new NdsError(
      "unknown-overlay-id",
      `Missing ${candidate.processor.toUpperCase()} overlay ${candidate.overlayId}`,
    );
  }
  return overlayCandidate(
    overlay,
    candidate.runtimeAddress,
    candidate.romOffset,
    candidate.kind === "overlay-bss",
  );
}

function codeMatchForProcessor(
  match: RomOffsetMatch,
  processor: NdsProcessor,
): boolean {
  if (processor === "arm9") {
    return match.kind === "arm9-main" || match.kind === "arm9-overlay";
  }
  return match.kind === "arm7-main" || match.kind === "arm7-overlay";
}

function fromRomMatch(
  map: NdsRomMap,
  processor: NdsProcessor,
  romOffset: number,
  match: RomOffsetMatch,
): NdsCodeSourceCandidate | null {
  if (match.kind === "arm9-main" || match.kind === "arm7-main") {
    if (match.runtimeAddress === null) {
      return null;
    }
    return mainCandidate(map, processor, match.runtimeAddress, romOffset);
  }

  if (match.overlayId === null || match.runtimeAddress === null) {
    return null;
  }
  const overlay = findOverlay(map, processor, match.overlayId);
  if (overlay === null) {
    throw new NdsError(
      "unknown-overlay-id",
      `Missing ${processor.toUpperCase()} overlay ${match.overlayId}`,
    );
  }
  if (overlay.compressed) {
    return null;
  }
  return overlayCandidate(
    overlay,
    match.runtimeAddress,
    romOffset,
    false,
  );
}

function filterOverlayId(
  candidates: readonly NdsCodeSourceCandidate[],
  overlayId: number | undefined,
): readonly NdsCodeSourceCandidate[] {
  if (overlayId === undefined) {
    return candidates;
  }
  return candidates.filter(
    (candidate) => candidate.component === "overlay"
      && candidate.overlayId === overlayId,
  );
}

function requireAlignment(address: number, mode: ArmMode): void {
  const alignment = mode === "arm" ? 4 : 2;
  if (address % alignment !== 0) {
    throw new NdsError(
      "range-out-of-bounds",
      `${mode.toUpperCase()} disassembly address must be ${alignment}-byte aligned`,
    );
  }
}

function requestedMode(
  map: NdsRomMap,
  candidate: NdsCodeSourceCandidate,
  requested: NdsDisassemblyMode,
): ArmMode | null {
  if (requested !== "auto") {
    return requested;
  }
  if (candidate.component !== "main" || candidate.runtimeAddress === null) {
    return null;
  }
  const executable = candidate.processor === "arm9"
    ? map.header.arm9
    : map.header.arm7;
  return candidate.runtimeAddress === executable.entryAddress ? "arm" : null;
}

function classifyCandidate(
  map: NdsRomMap,
  selectorAddress: number,
  processor: NdsProcessor,
  requested: NdsDisassemblyMode,
  candidates: readonly NdsCodeSourceCandidate[],
): NdsCodeSourceResolution {
  if (candidates.length === 0) {
    return { status: "unmapped-address", address: selectorAddress, processor };
  }
  if (candidates.length > 1) {
    return { status: "ambiguous-code-source", candidates };
  }

  const candidate = candidates[0];
  if (candidate === undefined) {
    return { status: "unmapped-address", address: selectorAddress, processor };
  }
  if (candidate.bss) {
    return { status: "runtime-only-bss", candidate };
  }
  if (
    candidate.runtimeAddress === null
    || candidate.runtimeImageOffset === null
    || candidate.representation === "runtime-only"
  ) {
    return { status: "unmapped-address", address: selectorAddress, processor };
  }
  if (
    candidate.runtimeAddress < candidate.runtimeStart
    || candidate.runtimeAddress >= candidate.runtimeEnd
  ) {
    return { status: "unmapped-address", address: selectorAddress, processor };
  }
  if (candidate.representation === "rom-file-backed") {
    if (
      candidate.romOffset === null
      || candidate.romStart === null
      || candidate.romEnd === null
      || candidate.romOffset < candidate.romStart
      || candidate.romOffset >= candidate.romEnd
    ) {
      return { status: "unmapped-address", address: selectorAddress, processor };
    }
  }

  const mode = requestedMode(map, candidate, requested);
  if (mode === null) {
    return {
      status: "mode-ambiguous",
      address: candidate.runtimeAddress,
      processor,
    };
  }
  requireAlignment(candidate.runtimeAddress, mode);
  return {
    status: "resolved",
    source: {
      processor: candidate.processor,
      component: candidate.component,
      overlayId: candidate.overlayId,
      runtimeAddress: candidate.runtimeAddress,
      romOffset: candidate.romOffset,
      runtimeImageOffset: candidate.runtimeImageOffset,
      runtimeStart: candidate.runtimeStart,
      runtimeEnd: candidate.runtimeEnd,
      romStart: candidate.romStart,
      romEnd: candidate.romEnd,
      representation: candidate.representation,
      mode,
    },
  };
}

function runtimeCandidates(
  map: NdsRomMap,
  address: number,
  processor: NdsProcessor,
): readonly NdsCodeSourceCandidate[] {
  const resolution = resolveRuntimeAddress(map, address, processor);
  if (resolution.status === "unmapped") {
    return [];
  }
  if (resolution.status === "ambiguous-runtime-address") {
    return resolution.candidates.map(
      (candidate) => fromRuntimeCandidate(map, candidate),
    );
  }
  return [fromRuntimeCandidate(map, resolution.candidate)];
}

function romCandidates(
  map: NdsRomMap,
  offset: number,
  processor: NdsProcessor,
): readonly NdsCodeSourceCandidate[] {
  const resolution = resolveRomOffset(map, offset);
  const candidates: NdsCodeSourceCandidate[] = [];
  for (const match of resolution.matches) {
    if (!codeMatchForProcessor(match, processor)) {
      continue;
    }
    const candidate = fromRomMatch(map, processor, offset, match);
    if (candidate !== null) {
      candidates.push(candidate);
    }
  }
  return candidates;
}

export function resolveNdsCodeSource(
  map: NdsRomMap,
  location: NdsDisassemblyLocation,
): NdsCodeSourceResolution {
  const locationKind = requireOneLocation(location);
  if (location.overlayId !== undefined) {
    requireUint32(location.overlayId, "Overlay ID");
  }

  if (locationKind === "runtime") {
    const address = location.runtimeAddress!;
    requireUint32(address, "Runtime address");
    const candidates = filterOverlayId(
      runtimeCandidates(map, address, location.processor),
      location.overlayId,
    );
    return classifyCandidate(
      map,
      address,
      location.processor,
      location.mode,
      candidates,
    );
  }

  const offset = location.romOffset!;
  requireUint32(offset, "ROM offset");
  const candidates = filterOverlayId(
    romCandidates(map, offset, location.processor),
    location.overlayId,
  );
  return classifyCandidate(
    map,
    offset,
    location.processor,
    location.mode,
    candidates,
  );
}

export function codeSourceAt(
  source: NdsCodeSource,
  runtimeAddress: number,
): NdsCodeSource {
  requireUint32(runtimeAddress, "Runtime address");
  if (
    runtimeAddress < source.runtimeStart
    || runtimeAddress >= source.runtimeEnd
  ) {
    throw new NdsError(
      "range-out-of-bounds",
      "Runtime address lies outside the selected code source",
    );
  }
  const relativeOffset = runtimeAddress - source.runtimeStart;
  return {
    ...source,
    runtimeAddress,
    runtimeImageOffset: relativeOffset,
    romOffset: source.representation === "rom-file-backed"
      && source.romStart !== null
      ? source.romStart + relativeOffset
      : null,
  };
}

export function resolveNdsControlFlowTarget(
  map: NdsRomMap,
  current: NdsCodeSource,
  runtimeAddress: number,
  mode: ArmMode,
): NdsCodeSourceResolution {
  requireUint32(runtimeAddress, "Runtime address");
  if (
    runtimeAddress >= current.runtimeStart
    && runtimeAddress < current.runtimeEnd
  ) {
    requireAlignment(runtimeAddress, mode);
    return {
      status: "resolved",
      source: {
        ...codeSourceAt(current, runtimeAddress),
        mode,
      },
    };
  }

  return resolveNdsCodeSource(map, {
    processor: current.processor,
    runtimeAddress,
    mode,
  });
}

function requireReadSize(maxBytes: number): void {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 0) {
    throw new NdsError(
      "range-out-of-bounds",
      "Disassembly read size must be a non-negative safe integer",
    );
  }
}

export async function withValidatedNdsCodeReader<T>(
  map: NdsRomMap,
  callback: (read: NdsCodeRead) => Promise<T>,
): Promise<T> {
  if (await hashFileSha256(map.romPath) !== map.sha256) {
    throw new NdsError(
      "invalid-rom",
      "Source ROM no longer matches the canonical map identity",
    );
  }

  const handle = await open(map.romPath, "r");
  const runtimeContext = createNdsOverlayRuntimeContext(map);
  let outcome:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: unknown };
  try {
    const value = await callback(async (source, maxBytes) => {
      requireReadSize(maxBytes);
      const runtimeRemaining = source.runtimeEnd - source.runtimeAddress;
      const requestedLength = Math.min(maxBytes, runtimeRemaining);

      if (source.representation === "rom-file-backed") {
        if (
          source.romOffset === null
          || source.romEnd === null
        ) {
          throw new NdsError(
            "range-out-of-bounds",
            "ROM-backed NDS code source unexpectedly lacks physical provenance",
          );
        }
        const length = Math.min(
          requestedLength,
          source.romEnd - source.romOffset,
        );
        return await readExact(
          handle,
          source.romOffset,
          length,
          "NDS disassembly source",
        );
      }

      if (source.overlayId === null) {
        throw new NdsError(
          "range-out-of-bounds",
          "Derived NDS code source unexpectedly lacks an overlay ID",
        );
      }
      const image = await runtimeContext.getCompressedOverlay(
        source.processor,
        source.overlayId,
      );
      if (
        image.runtimeAddress !== source.runtimeStart
        || image.runtimeSize !== source.runtimeEnd - source.runtimeStart
      ) {
        throw new NdsError(
          "compressed-overlay-runtime-unavailable",
          "Derived NDS code source no longer matches its canonical overlay runtime image",
        );
      }
      const start = source.runtimeImageOffset;
      const end = Math.min(start + requestedLength, image.bytes.length);
      if (start < 0 || start > image.bytes.length || end < start) {
        throw new NdsError(
          "range-out-of-bounds",
          "Derived NDS code source offset lies outside its runtime image",
        );
      }
      return image.bytes.subarray(start, end);
    });
    outcome = { ok: true, value };
  } catch (error) {
    outcome = { ok: false, error };
  } finally {
    await handle.close();
  }

  if (await hashFileSha256(map.romPath) !== map.sha256) {
    throw new NdsError(
      "invalid-rom",
      "Source ROM changed during disassembly",
    );
  }
  if (!outcome.ok) {
    throw outcome.error;
  }
  return outcome.value;
}

export async function withValidatedNdsRomReader<T>(
  map: NdsRomMap,
  callback: (read: NdsCodeRead) => Promise<T>,
): Promise<T> {
  return await withValidatedNdsCodeReader(map, callback);
}
