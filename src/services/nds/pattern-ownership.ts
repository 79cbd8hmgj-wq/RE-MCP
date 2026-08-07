import { NDS_PARSED_HEADER_BYTES } from "./header.js";
import type { NdsOverlay, NdsProcessor } from "./overlays.js";
import type { NdsRomMap } from "./rom-map.js";

export type NdsPatternOwner =
  | {
      readonly kind: "arm9-main" | "arm7-main";
      readonly processor: NdsProcessor;
      readonly runtimeAddress: number;
    }
  | {
      readonly kind: "arm9-overlay" | "arm7-overlay";
      readonly processor: NdsProcessor;
      readonly overlayId: number;
      readonly fileId: number;
      readonly compressed: boolean;
      readonly runtimeAddress: number | null;
    }
  | {
      readonly kind: "nitrofs-file";
      readonly fileId: number;
      readonly path: string | null;
    }
  | {
      readonly kind:
        | "header"
        | "fnt"
        | "fat"
        | "arm9-overlay-table"
        | "arm7-overlay-table";
    }
  | { readonly kind: "unmapped" };

function contains(
  hitStart: number,
  hitEnd: number,
  ownerStart: number,
  ownerEnd: number,
): boolean {
  return hitEnd > hitStart && hitStart >= ownerStart && hitEnd <= ownerEnd;
}

function mainOwner(
  map: NdsRomMap,
  processor: NdsProcessor,
  start: number,
  end: number,
): NdsPatternOwner | null {
  const executable = processor === "arm9" ? map.header.arm9 : map.header.arm7;
  if (!contains(start, end, executable.romOffset, executable.romEnd)) {
    return null;
  }
  return {
    kind: processor === "arm9" ? "arm9-main" : "arm7-main",
    processor,
    runtimeAddress: executable.ramAddress + (start - executable.romOffset),
  };
}

function overlayOwner(
  overlay: NdsOverlay,
  start: number,
  end: number,
): NdsPatternOwner | null {
  const storedEnd = overlay.romOffset + overlay.romSize;
  if (!contains(start, end, overlay.romOffset, storedEnd)) {
    return null;
  }
  const mappedBytes = Math.min(overlay.ramSize, overlay.romSize);
  const mappedEnd = overlay.romOffset + mappedBytes;
  const runtimeAddress = !overlay.compressed && end <= mappedEnd
    ? overlay.ramAddress + (start - overlay.romOffset)
    : null;
  return {
    kind: overlay.processor === "arm9" ? "arm9-overlay" : "arm7-overlay",
    processor: overlay.processor,
    overlayId: overlay.overlayId,
    fileId: overlay.fileId,
    compressed: overlay.compressed,
    runtimeAddress,
  };
}

function pushRegionOwner(
  owners: NdsPatternOwner[],
  kind: Extract<NdsPatternOwner, { readonly kind: "header" | "fnt" | "fat" | "arm9-overlay-table" | "arm7-overlay-table" }>["kind"],
  start: number,
  end: number,
  regionStart: number,
  regionEnd: number,
): void {
  if (contains(start, end, regionStart, regionEnd)) {
    owners.push({ kind });
  }
}

export function ownersForNdsPatternHit(
  map: NdsRomMap,
  start: number,
  end: number,
): readonly NdsPatternOwner[] {
  const owners: NdsPatternOwner[] = [];

  const arm9Main = mainOwner(map, "arm9", start, end);
  if (arm9Main !== null) owners.push(arm9Main);
  const arm7Main = mainOwner(map, "arm7", start, end);
  if (arm7Main !== null) owners.push(arm7Main);

  for (const overlay of map.overlays.arm9) {
    const owner = overlayOwner(overlay, start, end);
    if (owner !== null) owners.push(owner);
  }
  for (const overlay of map.overlays.arm7) {
    const owner = overlayOwner(overlay, start, end);
    if (owner !== null) owners.push(owner);
  }

  for (const file of map.filesystem.files) {
    if (contains(start, end, file.startOffset, file.endOffset)) {
      owners.push({
        kind: "nitrofs-file",
        fileId: file.fileId,
        path: file.path,
      });
    }
  }

  pushRegionOwner(owners, "header", start, end, 0, NDS_PARSED_HEADER_BYTES);
  pushRegionOwner(owners, "fnt", start, end, map.header.fnt.offset, map.header.fnt.end);
  pushRegionOwner(owners, "fat", start, end, map.header.fat.offset, map.header.fat.end);
  pushRegionOwner(
    owners,
    "arm9-overlay-table",
    start,
    end,
    map.header.arm9OverlayTable.offset,
    map.header.arm9OverlayTable.end,
  );
  pushRegionOwner(
    owners,
    "arm7-overlay-table",
    start,
    end,
    map.header.arm7OverlayTable.offset,
    map.header.arm7OverlayTable.end,
  );

  return owners.length === 0 ? [{ kind: "unmapped" }] : owners;
}
