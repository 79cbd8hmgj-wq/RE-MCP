import { NdsError } from "./errors.js";
import type { NdsProcessor } from "./overlays.js";
import type { NdsRomMap } from "./rom-map.js";

export type NdsPatternSearchScope =
  | { readonly kind: "whole-rom" }
  | {
      readonly kind: "components";
      readonly arm9Main?: boolean;
      readonly arm7Main?: boolean;
      readonly arm9OverlayIds?: readonly number[];
      readonly arm7OverlayIds?: readonly number[];
      readonly nitroFsFileIds?: readonly number[];
      readonly nitroFsPaths?: readonly string[];
    };

export type NdsPatternComponentKind =
  | "arm9-main"
  | "arm7-main"
  | "arm9-overlay"
  | "arm7-overlay"
  | "nitrofs-file";

export interface NdsPatternComponent {
  readonly key: string;
  readonly kind: NdsPatternComponentKind;
  readonly start: number;
  readonly end: number;
  readonly processor: NdsProcessor | null;
  readonly overlayId: number | null;
  readonly fileId: number | null;
  readonly path: string | null;
  readonly compressed: boolean;
}

export interface NdsPatternPhysicalRange {
  readonly start: number;
  readonly end: number;
}

export interface ResolvedNdsPatternScope {
  readonly kind: "whole-rom" | "components";
  readonly components: readonly NdsPatternComponent[];
  readonly physicalRanges: readonly NdsPatternPhysicalRange[];
}

export const NDS_PATTERN_MAX_OVERLAY_SELECTORS = 128;
export const NDS_PATTERN_MAX_NITROFS_SELECTORS = 256;
export const NDS_PATTERN_MAX_COMPONENTS = 256;

const KIND_ORDER: Readonly<Record<NdsPatternComponentKind, number>> = {
  "arm9-main": 0,
  "arm7-main": 1,
  "arm9-overlay": 2,
  "arm7-overlay": 3,
  "nitrofs-file": 4,
};

function limitExceeded(message: string): never {
  throw new NdsError("pattern-search-limit-exceeded", message);
}

function invalidScope(message: string): never {
  throw new NdsError("invalid-pattern-scope", message);
}

function mainComponent(
  map: NdsRomMap,
  processor: NdsProcessor,
): NdsPatternComponent {
  const executable = processor === "arm9" ? map.header.arm9 : map.header.arm7;
  return {
    key: `${processor}-main`,
    kind: processor === "arm9" ? "arm9-main" : "arm7-main",
    start: executable.romOffset,
    end: executable.romEnd,
    processor,
    overlayId: null,
    fileId: null,
    path: null,
    compressed: false,
  };
}

function overlayComponent(
  map: NdsRomMap,
  processor: NdsProcessor,
  overlayId: number,
): NdsPatternComponent {
  const overlays = processor === "arm9" ? map.overlays.arm9 : map.overlays.arm7;
  const overlay = overlays.find((candidate) => candidate.overlayId === overlayId);
  if (overlay === undefined) {
    throw new NdsError(
      "unknown-overlay-id",
      `Missing ${processor.toUpperCase()} overlay ${overlayId}`,
    );
  }
  return {
    key: `${processor}-overlay:${overlay.overlayId}`,
    kind: processor === "arm9" ? "arm9-overlay" : "arm7-overlay",
    start: overlay.romOffset,
    end: overlay.romOffset + overlay.romSize,
    processor,
    overlayId: overlay.overlayId,
    fileId: overlay.fileId,
    path: null,
    compressed: overlay.compressed,
  };
}

function fileById(map: NdsRomMap, fileId: number): NdsPatternComponent {
  const file = map.filesystem.files.find((candidate) => candidate.fileId === fileId);
  if (file === undefined) {
    throw new NdsError("unknown-file-id", `Missing NitroFS/FAT file ${fileId}`);
  }
  return {
    key: `nitrofs-file:${file.fileId}`,
    kind: "nitrofs-file",
    start: file.startOffset,
    end: file.endOffset,
    processor: null,
    overlayId: null,
    fileId: file.fileId,
    path: file.path,
    compressed: false,
  };
}

function fileByPath(map: NdsRomMap, filePath: string): NdsPatternComponent {
  const file = map.filesystem.files.find((candidate) => candidate.path === filePath);
  if (file === undefined) {
    throw new NdsError("unknown-file-id", `Missing NitroFS file path ${JSON.stringify(filePath)}`);
  }
  return fileById(map, file.fileId);
}

function componentOrder(left: NdsPatternComponent, right: NdsPatternComponent): number {
  const kindDifference = KIND_ORDER[left.kind] - KIND_ORDER[right.kind];
  if (kindDifference !== 0) return kindDifference;
  const leftOverlay = left.overlayId ?? Number.MAX_SAFE_INTEGER;
  const rightOverlay = right.overlayId ?? Number.MAX_SAFE_INTEGER;
  if (leftOverlay !== rightOverlay) return leftOverlay - rightOverlay;
  const leftFile = left.fileId ?? Number.MAX_SAFE_INTEGER;
  const rightFile = right.fileId ?? Number.MAX_SAFE_INTEGER;
  if (leftFile !== rightFile) return leftFile - rightFile;
  return left.key.localeCompare(right.key);
}

function normalizePhysicalRanges(
  components: readonly NdsPatternComponent[],
): readonly NdsPatternPhysicalRange[] {
  const ranges = components
    .filter((component) => component.end > component.start)
    .map((component) => ({ start: component.start, end: component.end }))
    .sort((left, right) => left.start - right.start || left.end - right.end);
  const merged: NdsPatternPhysicalRange[] = [];
  for (const range of ranges) {
    const current = merged[merged.length - 1];
    if (current === undefined || range.start > current.end) {
      merged.push({ ...range });
      continue;
    }
    merged[merged.length - 1] = {
      start: current.start,
      end: Math.max(current.end, range.end),
    };
  }
  return merged;
}

export function resolveNdsPatternScope(
  map: NdsRomMap,
  scope: NdsPatternSearchScope,
): ResolvedNdsPatternScope {
  if (scope.kind === "whole-rom") {
    return {
      kind: "whole-rom",
      components: [],
      physicalRanges: [{ start: 0, end: map.fileSize }],
    };
  }

  const arm9OverlayIds = scope.arm9OverlayIds ?? [];
  const arm7OverlayIds = scope.arm7OverlayIds ?? [];
  const nitroFsFileIds = scope.nitroFsFileIds ?? [];
  const nitroFsPaths = scope.nitroFsPaths ?? [];
  if (arm9OverlayIds.length + arm7OverlayIds.length > NDS_PATTERN_MAX_OVERLAY_SELECTORS) {
    limitExceeded(`Pattern scope accepts at most ${NDS_PATTERN_MAX_OVERLAY_SELECTORS} overlay selectors`);
  }
  if (nitroFsFileIds.length + nitroFsPaths.length > NDS_PATTERN_MAX_NITROFS_SELECTORS) {
    limitExceeded(`Pattern scope accepts at most ${NDS_PATTERN_MAX_NITROFS_SELECTORS} NitroFS selectors`);
  }

  const byKey = new Map<string, NdsPatternComponent>();
  const add = (component: NdsPatternComponent): void => {
    if (!byKey.has(component.key)) byKey.set(component.key, component);
  };

  if (scope.arm9Main === true) add(mainComponent(map, "arm9"));
  if (scope.arm7Main === true) add(mainComponent(map, "arm7"));
  for (const overlayId of arm9OverlayIds) add(overlayComponent(map, "arm9", overlayId));
  for (const overlayId of arm7OverlayIds) add(overlayComponent(map, "arm7", overlayId));
  for (const fileId of nitroFsFileIds) add(fileById(map, fileId));
  for (const filePath of nitroFsPaths) add(fileByPath(map, filePath));

  const components = [...byKey.values()].sort(componentOrder);
  if (components.length === 0) {
    invalidScope("Pattern component scope must select at least one canonical component");
  }
  if (components.length > NDS_PATTERN_MAX_COMPONENTS) {
    limitExceeded(`Pattern scope resolves to more than ${NDS_PATTERN_MAX_COMPONENTS} canonical components`);
  }

  return {
    kind: "components",
    components,
    physicalRanges: normalizePhysicalRanges(components),
  };
}

function containsSpan(
  start: number,
  end: number,
  containerStart: number,
  containerEnd: number,
): boolean {
  return end > start && start >= containerStart && end <= containerEnd;
}

export function patternSpanIsEligible(
  scope: ResolvedNdsPatternScope,
  start: number,
  end: number,
): boolean {
  if (scope.kind === "whole-rom") {
    const whole = scope.physicalRanges[0];
    return whole !== undefined && containsSpan(start, end, whole.start, whole.end);
  }
  return scope.components.some(
    (component) => containsSpan(start, end, component.start, component.end),
  );
}

export function selectPatternContextComponent(
  scope: ResolvedNdsPatternScope,
  start: number,
  end: number,
): NdsPatternComponent | null {
  if (scope.kind === "whole-rom") return null;
  const containing = scope.components.filter(
    (component) => containsSpan(start, end, component.start, component.end),
  );
  containing.sort((left, right) => {
    const spanDifference = (right.end - right.start) - (left.end - left.start);
    return spanDifference !== 0 ? spanDifference : componentOrder(left, right);
  });
  return containing[0] ?? null;
}
