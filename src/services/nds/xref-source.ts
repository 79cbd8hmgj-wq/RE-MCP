import type { ArmMode } from "../disassembly/backend.js";
import {
  resolveNdsCodeSource,
  type NdsCodeSource,
} from "./disassembly-source.js";
import { NdsError } from "./errors.js";
import type { NdsOverlay, NdsProcessor } from "./overlays.js";
import {
  resolveRomOffset,
  resolveRuntimeAddress,
  type RuntimeResolution,
} from "./resolver.js";
import type { NdsRomMap } from "./rom-map.js";

const UINT32_MAX = 0xffffffff;

export type NdsReferenceTargetSelector =
  | { readonly targetRuntimeAddress: number; readonly targetRomOffset?: never }
  | { readonly targetRomOffset: number; readonly targetRuntimeAddress?: never };

export type ReferenceSearchScope =
  | { readonly kind: "main" }
  | { readonly kind: "overlay"; readonly overlayIds: readonly number[] }
  | { readonly kind: "main-and-overlays"; readonly overlayIds: readonly number[] }
  | { readonly kind: "all-executable-components" };

export interface ReferenceSearchSeed {
  readonly runtimeAddress: number;
  readonly mode: ArmMode;
  readonly overlayId?: number | undefined;
}

export interface ReferenceComponentIdentity {
  readonly processor: NdsProcessor;
  readonly component: "main" | "overlay";
  readonly overlayId: number | null;
  readonly compressed: boolean;
}

export interface CanonicalReferenceTarget {
  readonly requestedBy: "runtime-address" | "rom-offset";
  readonly runtimeAddress: number;
  readonly romOffset: number | null;
  readonly resolution: RuntimeResolution;
}

export interface PreparedReferenceSearch {
  readonly processor: NdsProcessor;
  readonly target: CanonicalReferenceTarget;
  readonly components: readonly ReferenceComponentIdentity[];
  readonly explicitSeeds: readonly NdsCodeSource[];
}

function requireUint32(value: number, label: string): void {
  if (!Number.isInteger(value) || value < 0 || value > UINT32_MAX) {
    throw new NdsError(
      "range-out-of-bounds",
      `${label} must be a 32-bit unsigned integer`,
    );
  }
}

function canonicalizeTarget(
  map: NdsRomMap,
  processor: NdsProcessor,
  target: NdsReferenceTargetSelector,
): CanonicalReferenceTarget {
  const runtimeAddress = target.targetRuntimeAddress;
  const romOffset = target.targetRomOffset;
  const hasRuntime = runtimeAddress !== undefined;
  const hasRom = romOffset !== undefined;
  if (hasRuntime === hasRom) {
    throw new NdsError(
      "range-out-of-bounds",
      "Reference target requires exactly one runtime address or ROM offset",
    );
  }

  if (runtimeAddress !== undefined) {
    requireUint32(runtimeAddress, "Reference target runtime address");
    const resolution = resolveRuntimeAddress(map, runtimeAddress, processor);
    return {
      requestedBy: "runtime-address",
      runtimeAddress,
      romOffset: resolution.status === "resolved"
        ? resolution.candidate.romOffset
        : null,
      resolution,
    };
  }

  const offset = romOffset!;
  requireUint32(offset, "Reference target ROM offset");
  const matches = resolveRomOffset(map, offset).matches;
  const addresses = new Set<number>();
  for (const match of matches) {
    const processorMatch = processor === "arm9"
      ? match.kind === "arm9-main" || match.kind === "arm9-overlay"
      : match.kind === "arm7-main" || match.kind === "arm7-overlay";
    if (processorMatch && match.runtimeAddress !== null) {
      addresses.add(match.runtimeAddress >>> 0);
    }
  }

  const uniqueAddresses = [...addresses].sort((left, right) => left - right);
  if (uniqueAddresses.length === 0) {
    throw new NdsError(
      "reference-target-not-runtime-addressable",
      `ROM offset 0x${offset.toString(16)} has no runtime address for ${processor.toUpperCase()}`,
    );
  }
  if (uniqueAddresses.length > 1) {
    throw new NdsError(
      "ambiguous-reference-target",
      `ROM offset 0x${offset.toString(16)} maps to multiple ${processor.toUpperCase()} runtime addresses`,
    );
  }

  const address = uniqueAddresses[0]!;
  return {
    requestedBy: "rom-offset",
    runtimeAddress: address,
    romOffset: offset,
    resolution: resolveRuntimeAddress(map, address, processor),
  };
}

function overlaysFor(
  map: NdsRomMap,
  processor: NdsProcessor,
): readonly NdsOverlay[] {
  return processor === "arm9" ? map.overlays.arm9 : map.overlays.arm7;
}

function mainComponent(processor: NdsProcessor): ReferenceComponentIdentity {
  return {
    processor,
    component: "main",
    overlayId: null,
    compressed: false,
  };
}

function validateOverlayIds(
  map: NdsRomMap,
  processor: NdsProcessor,
  overlayIds: readonly number[],
): readonly NdsOverlay[] {
  if (overlayIds.length === 0) {
    throw new NdsError(
      "invalid-reference-scope",
      "Reference overlay scope requires at least one overlay ID",
    );
  }

  const seen = new Set<number>();
  for (const overlayId of overlayIds) {
    requireUint32(overlayId, "Reference scope overlay ID");
    if (seen.has(overlayId)) {
      throw new NdsError(
        "invalid-reference-scope",
        `Reference scope contains duplicate overlay ID ${overlayId}`,
      );
    }
    seen.add(overlayId);
  }

  const byId = new Map(
    overlaysFor(map, processor).map((overlay) => [overlay.overlayId, overlay] as const),
  );
  const overlays: NdsOverlay[] = [];
  for (const overlayId of seen) {
    const overlay = byId.get(overlayId);
    if (overlay === undefined) {
      throw new NdsError(
        "invalid-reference-scope",
        `${processor.toUpperCase()} overlay ${overlayId} does not exist`,
      );
    }
    overlays.push(overlay);
  }
  return overlays.sort((left, right) => left.overlayId - right.overlayId);
}

function overlayComponents(
  processor: NdsProcessor,
  overlays: readonly NdsOverlay[],
): readonly ReferenceComponentIdentity[] {
  return overlays.map((overlay) => ({
    processor,
    component: "overlay" as const,
    overlayId: overlay.overlayId,
    compressed: overlay.compressed,
  }));
}

function expandScope(
  map: NdsRomMap,
  processor: NdsProcessor,
  scope: ReferenceSearchScope,
): readonly ReferenceComponentIdentity[] {
  switch (scope.kind) {
    case "main":
      return [mainComponent(processor)];
    case "overlay":
      return overlayComponents(
        processor,
        validateOverlayIds(map, processor, scope.overlayIds),
      );
    case "main-and-overlays":
      return [
        mainComponent(processor),
        ...overlayComponents(
          processor,
          validateOverlayIds(map, processor, scope.overlayIds),
        ),
      ];
    case "all-executable-components":
      return [
        mainComponent(processor),
        ...overlayComponents(
          processor,
          [...overlaysFor(map, processor)].sort(
            (left, right) => left.overlayId - right.overlayId,
          ),
        ),
      ];
  }
}

function componentKey(component: ReferenceComponentIdentity): string {
  return component.component === "main"
    ? `${component.processor}:main`
    : `${component.processor}:overlay:${component.overlayId}`;
}

function sourceComponentKey(source: NdsCodeSource): string {
  return source.component === "main"
    ? `${source.processor}:main`
    : `${source.processor}:overlay:${source.overlayId}`;
}

function seedKey(source: NdsCodeSource): string {
  return [
    source.processor,
    source.component,
    source.overlayId ?? "main",
    source.runtimeAddress.toString(16),
    source.mode,
  ].join(":");
}

function validateSeeds(
  map: NdsRomMap,
  processor: NdsProcessor,
  components: readonly ReferenceComponentIdentity[],
  seeds: readonly ReferenceSearchSeed[],
): readonly NdsCodeSource[] {
  const selected = new Set(components.map(componentKey));
  const seen = new Set<string>();
  const resolvedSeeds: NdsCodeSource[] = [];

  for (const seed of seeds) {
    requireUint32(seed.runtimeAddress, "Reference seed runtime address");
    if (seed.overlayId !== undefined) {
      requireUint32(seed.overlayId, "Reference seed overlay ID");
    }
    const resolution = resolveNdsCodeSource(map, {
      processor,
      runtimeAddress: seed.runtimeAddress,
      mode: seed.mode,
      ...(seed.overlayId === undefined ? {} : { overlayId: seed.overlayId }),
    });
    if (resolution.status !== "resolved") {
      throw new NdsError(
        "invalid-reference-seed",
        `Reference seed at 0x${seed.runtimeAddress.toString(16)} did not resolve: ${resolution.status}`,
      );
    }
    if (!selected.has(sourceComponentKey(resolution.source))) {
      throw new NdsError(
        "invalid-reference-seed",
        `Reference seed at 0x${seed.runtimeAddress.toString(16)} lies outside the selected scope`,
      );
    }

    const key = seedKey(resolution.source);
    if (!seen.has(key)) {
      seen.add(key);
      resolvedSeeds.push(resolution.source);
    }
  }
  return resolvedSeeds;
}

export function prepareNdsReferenceSearch(
  map: NdsRomMap,
  processor: NdsProcessor,
  target: NdsReferenceTargetSelector,
  scope: ReferenceSearchScope,
  seeds: readonly ReferenceSearchSeed[],
): PreparedReferenceSearch {
  const components = expandScope(map, processor, scope);
  return {
    processor,
    target: canonicalizeTarget(map, processor, target),
    components,
    explicitSeeds: validateSeeds(map, processor, components, seeds),
  };
}
