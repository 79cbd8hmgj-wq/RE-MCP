import { NdsError } from "../errors.js";
import type { NdsNitroFile } from "../fnt.js";
import type { NdsOverlay, NdsProcessor } from "../overlays.js";
import {
  resolveRuntimeAddress,
  type RuntimeCandidate,
} from "../resolver.js";
import type { NdsRomMap } from "../rom-map.js";
import type {
  NdsMutationByteTarget,
  NdsMutationComponentSelector,
} from "./manifest.js";

export interface NdsMutationOverlayOwner {
  readonly processor: NdsProcessor;
  readonly overlayId: number;
  readonly compressed: boolean;
}

export interface NdsResolvedMutationComponent {
  readonly component: NdsMutationComponentSelector["component"];
  readonly processor: NdsProcessor | null;
  readonly overlayId: number | null;
  readonly fileId: number | null;
  readonly filePath: string | null;
  readonly romStart: number;
  readonly romEnd: number;
  readonly size: number;
  readonly compressed: boolean;
  readonly overlayOwners: readonly NdsMutationOverlayOwner[];
}

export interface NdsResolvedMutationRange {
  readonly component: NdsResolvedMutationComponent;
  readonly relativeOffset: number;
  readonly romStart: number;
  readonly romEnd: number;
  readonly size: number;
}

export interface NdsMutationPhysicalRange {
  readonly romStart: number;
  readonly romEnd: number;
  readonly labels: readonly string[];
}

function overlayOwnersForFile(
  map: NdsRomMap,
  fileId: number,
): readonly NdsMutationOverlayOwner[] {
  return [...map.overlays.arm9, ...map.overlays.arm7]
    .filter((overlay) => overlay.fileId === fileId)
    .map((overlay) => ({
      processor: overlay.processor,
      overlayId: overlay.overlayId,
      compressed: overlay.compressed,
    }))
    .sort((left, right) => {
      const processorOrder = left.processor.localeCompare(right.processor);
      return processorOrder !== 0
        ? processorOrder
        : left.overlayId - right.overlayId;
    });
}

function findOverlay(
  map: NdsRomMap,
  processor: NdsProcessor,
  overlayId: number,
): NdsOverlay {
  const overlays = processor === "arm9" ? map.overlays.arm9 : map.overlays.arm7;
  const overlay = overlays.find((candidate) => candidate.overlayId === overlayId);
  if (overlay === undefined) {
    throw new NdsError(
      "unknown-overlay-id",
      `${processor.toUpperCase()} overlay ${overlayId} does not exist`,
    );
  }
  return overlay;
}

function fileForId(map: NdsRomMap, fileId: number): NdsNitroFile {
  const file = map.filesystem.files.find((candidate) => candidate.fileId === fileId);
  if (file === undefined) {
    throw new NdsError("unknown-file-id", `NitroFS file ID ${fileId} does not exist`);
  }
  return file;
}

function fileForPath(map: NdsRomMap, filePath: string): NdsNitroFile {
  const matches = map.filesystem.files.filter((candidate) => candidate.path === filePath);
  if (matches.length !== 1 || matches[0] === undefined) {
    throw new NdsError(
      "unknown-file-id",
      `NitroFS path ${JSON.stringify(filePath)} does not resolve to exactly one canonical file`,
    );
  }
  return matches[0];
}

function componentForFile(
  map: NdsRomMap,
  selector: NdsMutationComponentSelector,
  file: NdsNitroFile,
): NdsResolvedMutationComponent {
  const overlayOwners = overlayOwnersForFile(map, file.fileId);
  if (overlayOwners.length > 0) {
    const owners = overlayOwners
      .map((owner) => `${owner.processor.toUpperCase()} overlay ${owner.overlayId}`)
      .join(", ");
    throw new NdsError(
      "unsupported-mutation-target",
      `NitroFS file ${file.fileId} backs ${owners}; use the explicit overlay selector for mutation`,
    );
  }
  return {
    component: selector.component,
    processor: null,
    overlayId: null,
    fileId: file.fileId,
    filePath: file.path,
    romStart: file.startOffset,
    romEnd: file.endOffset,
    size: file.size,
    compressed: false,
    overlayOwners: [],
  };
}

export function resolveNdsMutationComponent(
  map: NdsRomMap,
  selector: NdsMutationComponentSelector,
): NdsResolvedMutationComponent {
  if (selector.component === "arm9" || selector.component === "arm7") {
    const executable = selector.component === "arm9"
      ? map.header.arm9
      : map.header.arm7;
    return {
      component: selector.component,
      processor: selector.component,
      overlayId: null,
      fileId: null,
      filePath: null,
      romStart: executable.romOffset,
      romEnd: executable.romEnd,
      size: executable.size,
      compressed: false,
      overlayOwners: [],
    };
  }

  if (selector.component === "arm9-overlay" || selector.component === "arm7-overlay") {
    const processor = selector.component === "arm9-overlay" ? "arm9" : "arm7";
    const overlay = findOverlay(map, processor, selector.overlayId);
    const file = fileForId(map, overlay.fileId);
    return {
      component: selector.component,
      processor,
      overlayId: overlay.overlayId,
      fileId: overlay.fileId,
      filePath: file.path,
      romStart: overlay.romOffset,
      romEnd: overlay.romOffset + overlay.romSize,
      size: overlay.romSize,
      compressed: overlay.compressed,
      overlayOwners: overlayOwnersForFile(map, overlay.fileId),
    };
  }

  const file = selector.component === "nitrofs-file"
    ? fileForId(map, selector.fileId)
    : fileForPath(map, selector.filePath);
  return componentForFile(map, selector, file);
}

function checkedRange(
  component: NdsResolvedMutationComponent,
  relativeOffset: number,
  byteLength: number,
): NdsResolvedMutationRange {
  if (
    !Number.isSafeInteger(relativeOffset)
    || relativeOffset < 0
    || !Number.isSafeInteger(byteLength)
    || byteLength < 1
  ) {
    throw new NdsError(
      "unsupported-mutation-target",
      "Mutation byte range must use non-negative safe offsets and a positive safe length",
    );
  }
  const relativeEnd = relativeOffset + byteLength;
  if (
    !Number.isSafeInteger(relativeEnd)
    || relativeEnd < relativeOffset
    || relativeEnd > component.size
  ) {
    throw new NdsError(
      "unsupported-mutation-target",
      "Mutation byte range extends outside its canonical component",
    );
  }
  const romStart = component.romStart + relativeOffset;
  const romEnd = romStart + byteLength;
  return {
    component,
    relativeOffset,
    romStart,
    romEnd,
    size: byteLength,
  };
}

function exactOverlayRuntimeCandidate(
  map: NdsRomMap,
  processor: NdsProcessor,
  overlayId: number,
  runtimeAddress: number,
): RuntimeCandidate {
  const resolution = resolveRuntimeAddress(map, runtimeAddress, processor);
  const candidates = resolution.status === "ambiguous-runtime-address"
    ? resolution.candidates
    : resolution.status === "resolved"
      ? [resolution.candidate]
      : [];
  const matching = candidates.filter(
    (candidate) => candidate.overlayId === overlayId
      && candidate.processor === processor
      && candidate.representation === "rom-file-backed"
      && !candidate.compressed
      && candidate.romOffset !== null,
  );
  if (matching.length !== 1 || matching[0] === undefined) {
    if (resolution.status === "compressed-no-direct-rom-mapping") {
      throw new NdsError(
        "unsupported-mutation-target",
        "Decoded compressed-overlay runtime addresses are not writable in Milestone 1",
      );
    }
    throw new NdsError(
      "ambiguous-runtime-target",
      `Runtime address 0x${runtimeAddress.toString(16)} does not uniquely select ${processor.toUpperCase()} overlay ${overlayId}`,
    );
  }
  return matching[0];
}

function mainRuntimeCandidate(
  map: NdsRomMap,
  processor: NdsProcessor,
  runtimeAddress: number,
): RuntimeCandidate {
  const resolution = resolveRuntimeAddress(map, runtimeAddress, processor);
  if (
    resolution.status !== "resolved"
    || resolution.candidate.overlayId !== null
    || resolution.candidate.representation !== "rom-file-backed"
    || resolution.candidate.romOffset === null
  ) {
    throw new NdsError(
      "ambiguous-runtime-target",
      `Runtime address 0x${runtimeAddress.toString(16)} does not uniquely select ${processor.toUpperCase()} main`,
    );
  }
  return resolution.candidate;
}

function byteTargetComponentSelector(
  target: NdsMutationByteTarget,
): NdsMutationComponentSelector {
  switch (target.component) {
    case "arm9":
    case "arm7":
      return { component: target.component };
    case "arm9-overlay":
    case "arm7-overlay":
      return { component: target.component, overlayId: target.overlayId };
    case "nitrofs-file":
      return { component: target.component, fileId: target.fileId };
    case "nitrofs-path":
      return { component: target.component, filePath: target.filePath };
  }
}

export function resolveNdsMutationByteTarget(
  map: NdsRomMap,
  target: NdsMutationByteTarget,
  byteLength: number,
): NdsResolvedMutationRange {
  const component = resolveNdsMutationComponent(map, byteTargetComponentSelector(target));
  if (component.compressed) {
    throw new NdsError(
      "unsupported-mutation-target",
      "Byte edits to compressed overlays are not supported; replace the exact stored component instead",
    );
  }

  let relativeOffset: number;
  if ("relativeOffset" in target) {
    relativeOffset = target.relativeOffset;
  } else if (target.component === "arm9" || target.component === "arm7") {
    relativeOffset = mainRuntimeCandidate(
      map,
      target.component,
      target.runtimeAddress,
    ).relativeOffset;
  } else if (target.component === "arm9-overlay" || target.component === "arm7-overlay") {
    const processor = target.component === "arm9-overlay" ? "arm9" : "arm7";
    relativeOffset = exactOverlayRuntimeCandidate(
      map,
      processor,
      target.overlayId,
      target.runtimeAddress,
    ).relativeOffset;
  } else {
    throw new NdsError(
      "unsupported-mutation-target",
      "NitroFS byte edits require a component-relative offset",
    );
  }

  const range = checkedRange(component, relativeOffset, byteLength);
  assertMutationRangeOutsideStructure(map, range.romStart, range.romEnd);
  return range;
}

function rawStructuralRanges(map: NdsRomMap): NdsMutationPhysicalRange[] {
  const ranges: NdsMutationPhysicalRange[] = [
    {
      romStart: 0,
      romEnd: Math.min(0x200, map.fileSize),
      labels: ["header"],
    },
  ];
  for (const [label, region] of [
    ["fnt", map.header.fnt],
    ["fat", map.header.fat],
    ["arm9-overlay-table", map.header.arm9OverlayTable],
    ["arm7-overlay-table", map.header.arm7OverlayTable],
  ] as const) {
    if (region.size > 0) {
      ranges.push({
        romStart: region.offset,
        romEnd: region.end,
        labels: [label],
      });
    }
  }
  return ranges;
}

export function ndsImmutableStructuralRanges(
  map: NdsRomMap,
): readonly NdsMutationPhysicalRange[] {
  const sorted = rawStructuralRanges(map)
    .filter((range) => range.romEnd > range.romStart)
    .sort((left, right) => left.romStart - right.romStart || left.romEnd - right.romEnd);
  const merged: NdsMutationPhysicalRange[] = [];
  for (const range of sorted) {
    const previous = merged[merged.length - 1];
    if (previous === undefined || range.romStart > previous.romEnd) {
      merged.push(range);
      continue;
    }
    merged[merged.length - 1] = {
      romStart: previous.romStart,
      romEnd: Math.max(previous.romEnd, range.romEnd),
      labels: [...new Set([...previous.labels, ...range.labels])].sort(),
    };
  }
  return merged;
}

export function assertMutationRangeOutsideStructure(
  map: NdsRomMap,
  start: number,
  end: number,
): void {
  if (
    !Number.isSafeInteger(start)
    || !Number.isSafeInteger(end)
    || start < 0
    || end <= start
    || end > map.fileSize
  ) {
    throw new NdsError(
      "unsupported-mutation-target",
      "Mutation range lies outside the canonical ROM file",
    );
  }
  for (const range of ndsImmutableStructuralRanges(map)) {
    if (start < range.romEnd && end > range.romStart) {
      throw new NdsError(
        "structural-metadata-mutation",
        `Mutation range intersects immutable NDS structure: ${range.labels.join(", ")}`,
      );
    }
  }
}
