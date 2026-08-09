import type {
  ArmDisassemblyBackend,
  ArmMode,
} from "../disassembly/backend.js";
import {
  decodeNdsInstructionDetailed,
  type DetailedStaticInstruction,
} from "./disassembly.js";
import {
  codeSourceAt,
  resolveNdsCodeSource,
  withValidatedNdsCodeReader,
  type NdsCodeRead,
  type NdsCodeSource,
  type NdsCodeSourceResolution,
} from "./disassembly-source.js";
import { NdsError } from "./errors.js";
import type { NdsProcessor } from "./overlays.js";
import {
  classifyNdsInstructionReferences,
  compareStaticReferences,
  type StaticReference,
} from "./references.js";
import type { NdsRomMap } from "./rom-map.js";
import {
  prepareNdsReferenceSearch,
  type CanonicalReferenceTarget,
  type NdsReferenceTargetSelector,
  type ReferenceComponentIdentity,
  type ReferenceSearchScope,
  type ReferenceSearchSeed,
} from "./xref-source.js";

export interface ReferenceScanLimits {
  readonly maxComponents: number;
  readonly maxBlocks: number;
  readonly maxInstructions: number;
  readonly maxBytes: number;
  readonly maxEdges: number;
  readonly maxXrefs: number;
}

export type ReferenceTruncationReason =
  | "component-limit"
  | "block-limit"
  | "instruction-limit"
  | "byte-limit"
  | "edge-limit"
  | "result-limit";

export type ComponentCoverageStatus =
  | "scanned"
  | "no-proven-seed"
  | "out-of-limit";

export interface ReferenceComponentCoverage {
  readonly component: "main" | "overlay";
  readonly overlayId: number | null;
  readonly status: ComponentCoverageStatus;
}

export interface FindNdsXrefsRequest {
  readonly processor: NdsProcessor;
  readonly target: NdsReferenceTargetSelector;
  readonly scope: ReferenceSearchScope;
  readonly seeds: readonly ReferenceSearchSeed[];
}

export interface FindNdsXrefsResult {
  readonly status: "complete" | "partial-coverage" | "truncated";
  readonly target: CanonicalReferenceTarget;
  readonly scan: {
    readonly processor: NdsProcessor;
    readonly componentsRequested: number;
    readonly componentsScanned: number;
    readonly blocksDecoded: number;
    readonly instructionsDecoded: number;
    readonly decodedBytes: number;
    readonly traversalEdges: number;
  };
  readonly coverage: readonly ReferenceComponentCoverage[];
  readonly truncationReasons: readonly ReferenceTruncationReason[];
  readonly xrefs: readonly StaticReference[];
}

const TRUNCATION_REASON_ORDER: readonly ReferenceTruncationReason[] = [
  "component-limit",
  "block-limit",
  "instruction-limit",
  "byte-limit",
  "edge-limit",
  "result-limit",
];

function validatePositiveLimit(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new NdsError(
      "reference-scan-limit-exceeded",
      `${label} must be a positive safe integer`,
    );
  }
}

function validateLimits(limits: ReferenceScanLimits): void {
  validatePositiveLimit(limits.maxComponents, "Maximum component count");
  validatePositiveLimit(limits.maxBlocks, "Maximum block count");
  validatePositiveLimit(limits.maxInstructions, "Maximum instruction count");
  validatePositiveLimit(limits.maxBytes, "Maximum decoded byte count");
  validatePositiveLimit(limits.maxEdges, "Maximum traversal edge count");
  validatePositiveLimit(limits.maxXrefs, "Maximum returned xref count");
}

function componentKey(input: {
  readonly processor: NdsProcessor;
  readonly component: "main" | "overlay";
  readonly overlayId: number | null;
}): string {
  return input.component === "main"
    ? `${input.processor}:main`
    : `${input.processor}:overlay:${input.overlayId}`;
}

function blockKey(source: NdsCodeSource): string {
  return [
    source.processor,
    source.component,
    source.overlayId ?? "main",
    source.runtimeAddress.toString(16),
    source.mode,
  ].join(":");
}

function sameComponentSource(
  source: NdsCodeSource,
  runtimeAddress: number,
  mode: ArmMode,
): NdsCodeSource | null {
  if (
    runtimeAddress < source.runtimeStart
    || runtimeAddress >= source.runtimeEnd
  ) {
    return null;
  }
  return {
    ...codeSourceAt(source, runtimeAddress),
    mode,
  };
}

function resolvedTraversalSource(
  resolution: NdsCodeSourceResolution | null,
  processor: NdsProcessor,
  considered: ReadonlySet<string>,
): NdsCodeSource | null {
  if (resolution?.status !== "resolved") {
    return null;
  }
  const source = resolution.source;
  if (source.processor !== processor) {
    return null;
  }
  return considered.has(componentKey(source)) ? source : null;
}

function isMatchingReference(
  reference: StaticReference,
  target: CanonicalReferenceTarget,
): boolean {
  return reference.target.runtimeAddress === target.runtimeAddress;
}

export async function findNdsXrefsWithReader(
  map: NdsRomMap,
  request: FindNdsXrefsRequest,
  limits: ReferenceScanLimits,
  backend: ArmDisassemblyBackend,
  read: NdsCodeRead,
): Promise<FindNdsXrefsResult> {
  validateLimits(limits);
  const prepared = prepareNdsReferenceSearch(
    map,
    request.processor,
    request.target,
    request.scope,
    request.seeds,
  );
  const considered = prepared.components.slice(0, limits.maxComponents);
  const excluded = prepared.components.slice(limits.maxComponents);
  const consideredKeys = new Set(considered.map(componentKey));
  const reasons = new Set<ReferenceTruncationReason>();
  if (excluded.length > 0) {
    reasons.add("component-limit");
  }

  const initialCoverage = new Map<string, ComponentCoverageStatus>();
  for (const component of considered) {
    initialCoverage.set(componentKey(component), "no-proven-seed");
  }
  for (const component of excluded) {
    initialCoverage.set(componentKey(component), "out-of-limit");
  }

  const queue: NdsCodeSource[] = [];
  const scheduled = new Set<string>();
  const visited = new Set<string>();
  const seededComponents = new Set<string>();
  const limitedComponents = new Set<string>();
  const retainedXrefs: StaticReference[] = [];
  let totalMatchingReferences = 0;
  let totalInstructions = 0;
  let totalBytes = 0;
  let totalEdges = 0;
  let blocksDecoded = 0;

  function markSeeded(source: NdsCodeSource): void {
    seededComponents.add(componentKey(source));
  }

  function scheduleSource(source: NdsCodeSource): string | null {
    if (!consideredKeys.has(componentKey(source))) {
      return null;
    }
    markSeeded(source);
    const id = blockKey(source);
    if (scheduled.has(id)) {
      return id;
    }
    if (scheduled.size >= limits.maxBlocks) {
      reasons.add("block-limit");
      limitedComponents.add(componentKey(source));
      return null;
    }
    scheduled.add(id);
    queue.push(source);
    return id;
  }

  function traverseTo(
    currentComponent: string,
    source: NdsCodeSource | null,
  ): void {
    if (source === null) {
      return;
    }
    if (totalEdges >= limits.maxEdges) {
      reasons.add("edge-limit");
      limitedComponents.add(currentComponent);
      return;
    }
    totalEdges += 1;
    scheduleSource(source);
  }

  function collectReferences(detailed: DetailedStaticInstruction): void {
    for (const reference of classifyNdsInstructionReferences(map, detailed)) {
      if (!isMatchingReference(reference, prepared.target)) {
        continue;
      }
      totalMatchingReferences += 1;
      retainedXrefs.push(reference);
      retainedXrefs.sort(compareStaticReferences);
      if (retainedXrefs.length > limits.maxXrefs) {
        retainedXrefs.pop();
      }
    }
  }

  const main = considered.find((component) => component.component === "main");
  if (main !== undefined) {
    const executable = request.processor === "arm9"
      ? map.header.arm9
      : map.header.arm7;
    const entryResolution = resolveNdsCodeSource(map, {
      processor: request.processor,
      runtimeAddress: executable.entryAddress,
      mode: "arm",
    });
    if (entryResolution.status === "resolved") {
      scheduleSource(entryResolution.source);
    }
  }

  for (const seed of prepared.explicitSeeds) {
    if (consideredKeys.has(componentKey(seed))) {
      scheduleSource(seed);
    }
  }

  while (queue.length > 0) {
    if (
      totalInstructions >= limits.maxInstructions
      || totalBytes >= limits.maxBytes
    ) {
      if (totalInstructions >= limits.maxInstructions) {
        reasons.add("instruction-limit");
      }
      if (totalBytes >= limits.maxBytes) {
        reasons.add("byte-limit");
      }
      for (const pending of queue) {
        limitedComponents.add(componentKey(pending));
      }
      break;
    }

    const blockSource = queue.shift();
    if (blockSource === undefined) {
      break;
    }
    const id = blockKey(blockSource);
    if (visited.has(id)) {
      continue;
    }
    visited.add(id);
    blocksDecoded += 1;
    const currentComponent = componentKey(blockSource);
    let cursor = 0;
    const remainingByteBudget = limits.maxBytes - totalBytes;
    const bytes = remainingByteBudget > 0
      ? await read(blockSource, remainingByteBudget)
      : Buffer.alloc(0);

    while (true) {
      const currentAddress = blockSource.runtimeAddress + cursor;
      if (currentAddress >= blockSource.runtimeEnd) {
        break;
      }

      if (totalInstructions >= limits.maxInstructions) {
        reasons.add("instruction-limit");
        limitedComponents.add(currentComponent);
        break;
      }
      if (totalBytes >= limits.maxBytes) {
        reasons.add("byte-limit");
        limitedComponents.add(currentComponent);
        break;
      }

      const minimumInstructionSize = blockSource.mode === "arm" ? 4 : 2;
      const remainingWindow = bytes.length - cursor;
      if (remainingWindow < minimumInstructionSize) {
        const reachesComponentEnd = currentAddress + remainingWindow
          >= blockSource.runtimeEnd;
        if (!reachesComponentEnd) {
          reasons.add("byte-limit");
          limitedComponents.add(currentComponent);
        }
        break;
      }

      const currentSource = codeSourceAt(blockSource, currentAddress);
      const detailed = decodeNdsInstructionDetailed(
        map,
        currentSource,
        bytes.subarray(cursor),
        backend,
      );
      if (detailed === null) {
        break;
      }
      const instruction = detailed.instruction;
      if (totalBytes + instruction.size > limits.maxBytes) {
        reasons.add("byte-limit");
        limitedComponents.add(currentComponent);
        break;
      }

      totalInstructions += 1;
      totalBytes += instruction.size;
      cursor += instruction.size;
      collectReferences(detailed);

      const nextAddress = instruction.address + instruction.size;
      const nextInsideComponent = nextAddress < blockSource.runtimeEnd;

      switch (instruction.flow.kind) {
        case "fallthrough":
          if (nextInsideComponent) {
            continue;
          }
          break;

        case "call": {
          const target = resolvedTraversalSource(
            instruction.targetResolution,
            request.processor,
            consideredKeys,
          );
          traverseTo(currentComponent, target);
          if (nextInsideComponent && instruction.flow.fallthrough !== null) {
            continue;
          }
          break;
        }

        case "indirect-call":
          if (nextInsideComponent && instruction.flow.fallthrough !== null) {
            continue;
          }
          break;

        case "conditional-branch": {
          const taken = resolvedTraversalSource(
            instruction.targetResolution,
            request.processor,
            consideredKeys,
          );
          traverseTo(currentComponent, taken);

          const fallthrough = instruction.flow.fallthrough;
          if (fallthrough !== null) {
            const fallthroughSource = sameComponentSource(
              blockSource,
              fallthrough,
              instruction.mode,
            );
            traverseTo(currentComponent, fallthroughSource);
          }
          break;
        }

        case "unconditional-branch": {
          const target = resolvedTraversalSource(
            instruction.targetResolution,
            request.processor,
            consideredKeys,
          );
          traverseTo(currentComponent, target);
          break;
        }

        case "return":
        case "indirect-branch":
          break;
      }
      break;
    }
  }

  if (totalMatchingReferences > limits.maxXrefs) {
    reasons.add("result-limit");
  }

  for (const source of queue) {
    if (!visited.has(blockKey(source))) {
      limitedComponents.add(componentKey(source));
    }
  }

  const coverage: ReferenceComponentCoverage[] = prepared.components.map(
    (component: ReferenceComponentIdentity) => {
      const key = componentKey(component);
      const initial = initialCoverage.get(key);
      let status: ComponentCoverageStatus;
      if (initial === "out-of-limit") {
        status = initial;
      } else if (!seededComponents.has(key)) {
        status = "no-proven-seed";
      } else if (limitedComponents.has(key)) {
        status = "out-of-limit";
      } else {
        status = "scanned";
      }
      return {
        component: component.component,
        overlayId: component.overlayId,
        status,
      };
    },
  );

  const truncationReasons = TRUNCATION_REASON_ORDER.filter(
    (reason) => reasons.has(reason),
  );
  const componentsScanned = coverage.filter(
    (entry) => entry.status === "scanned",
  ).length;
  const hasCoverageGap = coverage.some((entry) => entry.status !== "scanned");
  const status: FindNdsXrefsResult["status"] = truncationReasons.length > 0
    ? "truncated"
    : hasCoverageGap
      ? "partial-coverage"
      : "complete";

  return {
    status,
    target: prepared.target,
    scan: {
      processor: request.processor,
      componentsRequested: prepared.components.length,
      componentsScanned,
      blocksDecoded,
      instructionsDecoded: totalInstructions,
      decodedBytes: totalBytes,
      traversalEdges: totalEdges,
    },
    coverage,
    truncationReasons,
    xrefs: retainedXrefs,
  };
}

export async function findNdsXrefs(
  map: NdsRomMap,
  request: FindNdsXrefsRequest,
  limits: ReferenceScanLimits,
  backend: ArmDisassemblyBackend,
): Promise<FindNdsXrefsResult> {
  return await withValidatedNdsCodeReader(
    map,
    (read) => findNdsXrefsWithReader(map, request, limits, backend, read),
  );
}
