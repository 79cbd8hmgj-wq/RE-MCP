import { NdsError } from "./errors.js";
import type { NdsOverlay, NdsProcessor } from "./overlays.js";
import type { NdsRomMap } from "./rom-map.js";

const UINT32_MAX = 0xffffffff;
const NDS_HEADER_REGION_END = 0x200;

export interface RuntimeCandidate {
  readonly kind: "arm9-main" | "arm7-main" | "arm9-overlay" | "arm7-overlay" | "overlay-bss";
  readonly processor: NdsProcessor;
  readonly runtimeAddress: number;
  readonly relativeOffset: number;
  readonly overlayId: number | null;
  readonly fileId: number | null;
  readonly romOffset: number | null;
  readonly backingRomOffset: number | null;
  readonly backingRomSize: number | null;
  readonly compressed: boolean;
}

export type RuntimeResolution =
  | { readonly status: "unmapped"; readonly address: number; readonly processor: NdsProcessor }
  | { readonly status: "resolved"; readonly candidate: RuntimeCandidate }
  | { readonly status: "ambiguous-runtime-address"; readonly candidates: readonly RuntimeCandidate[] }
  | { readonly status: "runtime-only-bss"; readonly candidate: RuntimeCandidate }
  | { readonly status: "compressed-no-direct-rom-mapping"; readonly candidate: RuntimeCandidate };

export interface RomOffsetMatch {
  readonly kind:
    | "header"
    | "fnt"
    | "fat"
    | "arm9-overlay-table"
    | "arm7-overlay-table"
    | "nitrofs-file"
    | "arm9-main"
    | "arm7-main"
    | "arm9-overlay"
    | "arm7-overlay";
  readonly fileId: number | null;
  readonly overlayId: number | null;
  readonly runtimeAddress: number | null;
}

export interface RomOffsetResolution {
  readonly offset: number;
  readonly matches: readonly RomOffsetMatch[];
}

function requireUint32(value: number, label: string): void {
  if (!Number.isInteger(value) || value < 0 || value > UINT32_MAX) {
    throw new NdsError("range-out-of-bounds", `${label} must be a 32-bit unsigned integer`);
  }
}

function overlayCandidate(overlay: NdsOverlay, address: number): RuntimeCandidate | null {
  if (address < overlay.ramAddress || address >= overlay.bssEnd) {
    return null;
  }

  const relativeOffset = address - overlay.ramAddress;
  if (address >= overlay.ramEnd) {
    return {
      kind: "overlay-bss",
      processor: overlay.processor,
      runtimeAddress: address,
      relativeOffset,
      overlayId: overlay.overlayId,
      fileId: overlay.fileId,
      romOffset: null,
      backingRomOffset: overlay.romOffset,
      backingRomSize: overlay.romSize,
      compressed: overlay.compressed,
    };
  }

  const directRomOffset = !overlay.compressed && relativeOffset < overlay.romSize
    ? overlay.romOffset + relativeOffset
    : null;
  return {
    kind: overlay.processor === "arm9" ? "arm9-overlay" : "arm7-overlay",
    processor: overlay.processor,
    runtimeAddress: address,
    relativeOffset,
    overlayId: overlay.overlayId,
    fileId: overlay.fileId,
    romOffset: directRomOffset,
    backingRomOffset: overlay.romOffset,
    backingRomSize: overlay.romSize,
    compressed: overlay.compressed,
  };
}

export function resolveRuntimeAddress(
  map: NdsRomMap,
  address: number,
  processor: NdsProcessor,
): RuntimeResolution {
  requireUint32(address, "Runtime address");
  const candidates: RuntimeCandidate[] = [];
  const executable = processor === "arm9" ? map.header.arm9 : map.header.arm7;
  if (address >= executable.ramAddress && address < executable.ramEnd) {
    const relativeOffset = address - executable.ramAddress;
    candidates.push({
      kind: processor === "arm9" ? "arm9-main" : "arm7-main",
      processor,
      runtimeAddress: address,
      relativeOffset,
      overlayId: null,
      fileId: null,
      romOffset: executable.romOffset + relativeOffset,
      backingRomOffset: executable.romOffset,
      backingRomSize: executable.size,
      compressed: false,
    });
  }

  const overlays = processor === "arm9" ? map.overlays.arm9 : map.overlays.arm7;
  for (const overlay of overlays) {
    const candidate = overlayCandidate(overlay, address);
    if (candidate !== null) {
      candidates.push(candidate);
    }
  }

  if (candidates.length === 0) {
    return { status: "unmapped", address, processor };
  }
  if (candidates.length > 1) {
    return { status: "ambiguous-runtime-address", candidates };
  }

  const candidate = candidates[0];
  if (candidate === undefined) {
    return { status: "unmapped", address, processor };
  }
  if (candidate.kind === "overlay-bss") {
    return { status: "runtime-only-bss", candidate };
  }
  if (candidate.compressed && candidate.overlayId !== null) {
    return { status: "compressed-no-direct-rom-mapping", candidate };
  }
  return { status: "resolved", candidate };
}

function contains(offset: number, start: number, end: number): boolean {
  return offset >= start && offset < end;
}

function structuralMatch(kind: RomOffsetMatch["kind"]): RomOffsetMatch {
  return { kind, fileId: null, overlayId: null, runtimeAddress: null };
}

export function resolveRomOffset(map: NdsRomMap, offset: number): RomOffsetResolution {
  if (!Number.isInteger(offset) || offset < 0 || offset >= map.fileSize) {
    throw new NdsError("range-out-of-bounds", "ROM offset lies outside the source file");
  }

  const matches: RomOffsetMatch[] = [];
  if (offset < Math.min(NDS_HEADER_REGION_END, map.fileSize)) {
    matches.push(structuralMatch("header"));
  }
  if (map.header.fnt.size > 0 && contains(offset, map.header.fnt.offset, map.header.fnt.end)) {
    matches.push(structuralMatch("fnt"));
  }
  if (map.header.fat.size > 0 && contains(offset, map.header.fat.offset, map.header.fat.end)) {
    matches.push(structuralMatch("fat"));
  }
  if (
    map.header.arm9OverlayTable.size > 0
    && contains(offset, map.header.arm9OverlayTable.offset, map.header.arm9OverlayTable.end)
  ) {
    matches.push(structuralMatch("arm9-overlay-table"));
  }
  if (
    map.header.arm7OverlayTable.size > 0
    && contains(offset, map.header.arm7OverlayTable.offset, map.header.arm7OverlayTable.end)
  ) {
    matches.push(structuralMatch("arm7-overlay-table"));
  }

  const arm9 = map.header.arm9;
  if (contains(offset, arm9.romOffset, arm9.romEnd)) {
    matches.push({
      kind: "arm9-main",
      fileId: null,
      overlayId: null,
      runtimeAddress: arm9.ramAddress + (offset - arm9.romOffset),
    });
  }
  const arm7 = map.header.arm7;
  if (contains(offset, arm7.romOffset, arm7.romEnd)) {
    matches.push({
      kind: "arm7-main",
      fileId: null,
      overlayId: null,
      runtimeAddress: arm7.ramAddress + (offset - arm7.romOffset),
    });
  }

  for (const file of map.filesystem.files) {
    if (contains(offset, file.startOffset, file.endOffset)) {
      matches.push({
        kind: "nitrofs-file",
        fileId: file.fileId,
        overlayId: null,
        runtimeAddress: null,
      });
    }
  }

  for (const overlay of [...map.overlays.arm9, ...map.overlays.arm7]) {
    if (!contains(offset, overlay.romOffset, overlay.romOffset + overlay.romSize)) {
      continue;
    }
    const relativeOffset = offset - overlay.romOffset;
    const runtimeAddress = !overlay.compressed && relativeOffset < overlay.ramSize
      ? overlay.ramAddress + relativeOffset
      : null;
    matches.push({
      kind: overlay.processor === "arm9" ? "arm9-overlay" : "arm7-overlay",
      fileId: overlay.fileId,
      overlayId: overlay.overlayId,
      runtimeAddress,
    });
  }

  return { offset, matches };
}
