import type { ArmMode } from "../disassembly/backend.js";
import {
  resolveNdsCodeSource,
  type NdsCodeSource,
} from "./disassembly-source.js";
import {
  NdsError,
  type AnyNdsErrorCategory,
  type NdsFunctionErrorCategory,
} from "./errors.js";
import {
  type FunctionProof,
  type ProvenFunctionIdentity,
} from "./function-model.js";
import type { NdsOverlay, NdsProcessor } from "./overlays.js";
import type { NdsRomMap } from "./rom-map.js";

const UINT32_MAX = 0xffffffff;

export type FunctionSearchScope =
  | { readonly kind: "main" }
  | { readonly kind: "overlay"; readonly overlayIds: readonly number[] }
  | { readonly kind: "main-and-overlays"; readonly overlayIds: readonly number[] }
  | { readonly kind: "all-executable-components" };

export interface FunctionSearchSeed {
  readonly runtimeAddress: number;
  readonly mode: ArmMode;
  readonly overlayId?: number | undefined;
}

export interface FunctionComponentIdentity {
  readonly processor: NdsProcessor;
  readonly component: "main" | "overlay";
  readonly overlayId: number | null;
  readonly compressed: boolean;
}

export interface PreparedFunctionSearch {
  readonly components: readonly FunctionComponentIdentity[];
  readonly explicitSeeds: readonly NdsCodeSource[];
  readonly programEntry: {
    readonly identity: ProvenFunctionIdentity;
    readonly source: NdsCodeSource;
    readonly proof: Extract<FunctionProof, { readonly kind: "program-entry" }>;
  } | null;
}

function functionError(
  category: NdsFunctionErrorCategory,
  message: string,
): NdsError<AnyNdsErrorCategory> {
  return new NdsError(category as AnyNdsErrorCategory, message);
}

function errorCategory(error: unknown): string | null {
  return error instanceof NdsError ? String(error.category) : null;
}

function requireUint32(
  value: number,
  label: string,
  category: "invalid-function-scope" | "invalid-function-seed",
): void {
  if (!Number.isInteger(value) || value < 0 || value > UINT32_MAX) {
    throw functionError(category, `${label} must be a 32-bit unsigned integer`);
  }
}

function overlaysFor(
  map: NdsRomMap,
  processor: NdsProcessor,
): readonly NdsOverlay[] {
  return processor === "arm9" ? map.overlays.arm9 : map.overlays.arm7;
}

function mainComponent(processor: NdsProcessor): FunctionComponentIdentity {
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
    throw functionError(
      "invalid-function-scope",
      "Function overlay scope requires at least one overlay ID",
    );
  }

  const seen = new Set<number>();
  for (const overlayId of overlayIds) {
    requireUint32(overlayId, "Function scope overlay ID", "invalid-function-scope");
    if (seen.has(overlayId)) {
      throw functionError(
        "invalid-function-scope",
        `Function scope contains duplicate overlay ID ${overlayId}`,
      );
    }
    seen.add(overlayId);
  }

  const byId = new Map(
    overlaysFor(map, processor).map((overlay) => [overlay.overlayId, overlay] as const),
  );
  const selected: NdsOverlay[] = [];
  for (const overlayId of seen) {
    const overlay = byId.get(overlayId);
    if (overlay === undefined) {
      throw functionError(
        "invalid-function-scope",
        `${processor.toUpperCase()} overlay ${overlayId} does not exist`,
      );
    }
    selected.push(overlay);
  }
  return selected.sort((left, right) => left.overlayId - right.overlayId);
}

function overlayComponents(
  processor: NdsProcessor,
  overlays: readonly NdsOverlay[],
): readonly FunctionComponentIdentity[] {
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
  scope: FunctionSearchScope,
): readonly FunctionComponentIdentity[] {
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

export function functionComponentKey(input: {
  readonly processor: NdsProcessor;
  readonly component: "main" | "overlay";
  readonly overlayId: number | null;
}): string {
  return input.component === "main"
    ? `${input.processor}:main`
    : `${input.processor}:overlay:${input.overlayId}`;
}

function seedKey(source: NdsCodeSource): string {
  return [
    functionComponentKey(source),
    source.runtimeAddress.toString(16),
    source.mode,
  ].join(":");
}

function resolveSeed(
  map: NdsRomMap,
  processor: NdsProcessor,
  seed: FunctionSearchSeed,
): NdsCodeSource {
  requireUint32(seed.runtimeAddress, "Function seed runtime address", "invalid-function-seed");
  if (seed.overlayId !== undefined) {
    requireUint32(seed.overlayId, "Function seed overlay ID", "invalid-function-seed");
  }

  try {
    const resolution = resolveNdsCodeSource(map, {
      processor,
      runtimeAddress: seed.runtimeAddress,
      mode: seed.mode,
      ...(seed.overlayId === undefined ? {} : { overlayId: seed.overlayId }),
    });
    if (resolution.status !== "resolved") {
      throw functionError(
        "invalid-function-seed",
        `Function seed at 0x${seed.runtimeAddress.toString(16)} did not resolve: ${resolution.status}`,
      );
    }
    return resolution.source;
  } catch (error) {
    if (errorCategory(error) === "invalid-function-seed") {
      throw error;
    }
    const message = error instanceof Error ? error.message : String(error);
    throw functionError(
      "invalid-function-seed",
      `Function seed at 0x${seed.runtimeAddress.toString(16)} is invalid: ${message}`,
    );
  }
}

function validateSeeds(
  map: NdsRomMap,
  processor: NdsProcessor,
  components: readonly FunctionComponentIdentity[],
  seeds: readonly FunctionSearchSeed[],
): readonly NdsCodeSource[] {
  const selected = new Set(components.map(functionComponentKey));
  const seen = new Set<string>();
  const resolved: NdsCodeSource[] = [];

  for (const seed of seeds) {
    const source = resolveSeed(map, processor, seed);
    if (!selected.has(functionComponentKey(source))) {
      throw functionError(
        "invalid-function-seed",
        `Function seed at 0x${seed.runtimeAddress.toString(16)} lies outside the selected scope`,
      );
    }

    const key = seedKey(source);
    if (!seen.has(key)) {
      seen.add(key);
      resolved.push(source);
    }
  }

  return resolved;
}

function identityFromSource(source: NdsCodeSource): ProvenFunctionIdentity {
  return {
    processor: source.processor,
    component: source.component,
    overlayId: source.overlayId,
    runtimeAddress: source.runtimeAddress,
    romOffset: source.romOffset,
    mode: source.mode,
  };
}

function programEntryFor(
  map: NdsRomMap,
  processor: NdsProcessor,
  selected: ReadonlySet<string>,
): PreparedFunctionSearch["programEntry"] {
  if (!selected.has(`${processor}:main`)) {
    return null;
  }

  const executable = processor === "arm9" ? map.header.arm9 : map.header.arm7;
  let resolution;
  try {
    resolution = resolveNdsCodeSource(map, {
      processor,
      runtimeAddress: executable.entryAddress,
      mode: "arm",
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw functionError(
      "function-entry-not-uniquely-resolved",
      `${processor.toUpperCase()} program entry could not be resolved: ${message}`,
    );
  }

  if (resolution.status !== "resolved" || resolution.source.component !== "main") {
    throw functionError(
      "function-entry-not-uniquely-resolved",
      `${processor.toUpperCase()} program entry did not resolve uniquely to main executable code`,
    );
  }

  const identity = identityFromSource(resolution.source);
  return {
    identity,
    source: resolution.source,
    proof: {
      kind: "program-entry",
      processor,
      headerEntryAddress: executable.entryAddress,
    },
  };
}

export function prepareFunctionSearch(
  map: NdsRomMap,
  processor: NdsProcessor,
  scope: FunctionSearchScope,
  seeds: readonly FunctionSearchSeed[],
): PreparedFunctionSearch {
  const components = expandScope(map, processor, scope);
  const selected = new Set(components.map(functionComponentKey));
  return {
    components,
    explicitSeeds: validateSeeds(map, processor, components, seeds),
    programEntry: programEntryFor(map, processor, selected),
  };
}

export function canonicalizeFunctionTarget(
  map: NdsRomMap,
  processor: NdsProcessor,
  runtimeAddress: number,
  mode: ArmMode,
  allowedComponents: ReadonlySet<string>,
): ProvenFunctionIdentity | null {
  if (!Number.isInteger(runtimeAddress) || runtimeAddress < 0 || runtimeAddress > UINT32_MAX) {
    return null;
  }

  let resolution;
  try {
    resolution = resolveNdsCodeSource(map, {
      processor,
      runtimeAddress,
      mode,
    });
  } catch {
    return null;
  }
  if (resolution.status !== "resolved") {
    return null;
  }
  if (!allowedComponents.has(functionComponentKey(resolution.source))) {
    return null;
  }
  return identityFromSource(resolution.source);
}
