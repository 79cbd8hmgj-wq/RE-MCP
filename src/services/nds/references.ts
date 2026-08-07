import type { ArmMode } from "../disassembly/backend.js";
import type { DetailedStaticInstruction } from "./disassembly.js";
import type { NdsProcessor } from "./overlays.js";
import {
  resolveRuntimeAddress,
  type RuntimeResolution,
} from "./resolver.js";
import type { NdsRomMap } from "./rom-map.js";

const UINT32_MASK = 0xffff_ffffn;

export type StaticReferenceKind =
  | "direct-branch"
  | "direct-call"
  | "literal-pool"
  | "pc-relative-address";

export type StaticReferenceMechanism =
  | "direct-control-flow"
  | "pc-relative-literal-address"
  | "pc-relative-address-construction";

export interface StaticReference {
  readonly kind: StaticReferenceKind;
  readonly source: {
    readonly processor: NdsProcessor;
    readonly component: "main" | "overlay";
    readonly overlayId: number | null;
    readonly instructionAddress: number;
    readonly instructionRomOffset: number;
    readonly mode: ArmMode;
  };
  readonly target: {
    readonly runtimeAddress: number;
    readonly romOffset: number | null;
    readonly mode: ArmMode | null;
    readonly resolution: RuntimeResolution;
  };
  readonly evidence: {
    readonly instructionMnemonic: string;
    readonly mechanism: StaticReferenceMechanism;
  };
}

function architecturalPc(address: number, mode: ArmMode): number {
  return mode === "arm"
    ? (address + 8) >>> 0
    : ((address + 4) & ~3) >>> 0;
}

function addUint32(base: number, delta: number): number {
  return Number((BigInt(base >>> 0) + BigInt(delta)) & UINT32_MASK);
}

function subtractUint32(base: number, delta: number): number {
  return Number((BigInt(base >>> 0) - BigInt(delta)) & UINT32_MASK);
}

function referenceTarget(
  map: NdsRomMap,
  processor: NdsProcessor,
  runtimeAddress: number,
  mode: ArmMode | null,
): StaticReference["target"] {
  const resolution = resolveRuntimeAddress(map, runtimeAddress, processor);
  return {
    runtimeAddress,
    romOffset: resolution.status === "resolved"
      ? resolution.candidate.romOffset
      : null,
    mode,
    resolution,
  };
}

function reference(
  map: NdsRomMap,
  detailed: DetailedStaticInstruction,
  kind: StaticReferenceKind,
  runtimeAddress: number,
  targetMode: ArmMode | null,
  mechanism: StaticReferenceMechanism,
): StaticReference {
  const { instruction } = detailed;
  return {
    kind,
    source: {
      processor: instruction.source.processor,
      component: instruction.source.component,
      overlayId: instruction.source.overlayId,
      instructionAddress: instruction.address,
      instructionRomOffset: instruction.romOffset,
      mode: instruction.mode,
    },
    target: referenceTarget(
      map,
      instruction.source.processor,
      runtimeAddress >>> 0,
      targetMode,
    ),
    evidence: {
      instructionMnemonic: instruction.mnemonic,
      mechanism,
    },
  };
}

export function classifyNdsInstructionReferences(
  map: NdsRomMap,
  detailed: DetailedStaticInstruction,
): readonly StaticReference[] {
  const { instruction, decoded } = detailed;
  const references: StaticReference[] = [];

  if (
    (
      instruction.flow.kind === "conditional-branch"
      || instruction.flow.kind === "unconditional-branch"
    )
    && instruction.flow.directTarget !== null
  ) {
    references.push(reference(
      map,
      detailed,
      "direct-branch",
      instruction.flow.directTarget,
      instruction.flow.targetMode,
      "direct-control-flow",
    ));
  }

  if (
    instruction.flow.kind === "call"
    && instruction.flow.directTarget !== null
  ) {
    references.push(reference(
      map,
      detailed,
      "direct-call",
      instruction.flow.directTarget,
      instruction.flow.targetMode,
      "direct-control-flow",
    ));
  }

  const pcRelative = decoded.pcRelative ?? null;
  if (pcRelative === null) {
    return references;
  }

  const pc = architecturalPc(instruction.address, instruction.mode);
  switch (pcRelative.kind) {
    case "literal-load":
      references.push(reference(
        map,
        detailed,
        "literal-pool",
        addUint32(pc, pcRelative.displacement),
        null,
        "pc-relative-literal-address",
      ));
      break;
    case "address-add":
      references.push(reference(
        map,
        detailed,
        "pc-relative-address",
        addUint32(pc, pcRelative.immediate),
        null,
        "pc-relative-address-construction",
      ));
      break;
    case "address-sub":
      references.push(reference(
        map,
        detailed,
        "pc-relative-address",
        subtractUint32(pc, pcRelative.immediate),
        null,
        "pc-relative-address-construction",
      ));
      break;
  }

  return references;
}

const PROCESSOR_ORDER: Record<NdsProcessor, number> = {
  arm9: 0,
  arm7: 1,
};

const MODE_ORDER: Record<ArmMode, number> = {
  arm: 0,
  thumb: 1,
};

const REFERENCE_KIND_ORDER: Record<StaticReferenceKind, number> = {
  "direct-branch": 0,
  "direct-call": 1,
  "literal-pool": 2,
  "pc-relative-address": 3,
};

function compareNumber(left: number, right: number): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function targetModeOrder(mode: ArmMode | null): number {
  return mode === null ? 2 : MODE_ORDER[mode];
}

export function compareStaticReferences(
  left: StaticReference,
  right: StaticReference,
): number {
  let compared = compareNumber(
    PROCESSOR_ORDER[left.source.processor],
    PROCESSOR_ORDER[right.source.processor],
  );
  if (compared !== 0) return compared;

  compared = compareNumber(
    left.source.component === "main" ? 0 : 1,
    right.source.component === "main" ? 0 : 1,
  );
  if (compared !== 0) return compared;

  compared = compareNumber(
    left.source.overlayId ?? -1,
    right.source.overlayId ?? -1,
  );
  if (compared !== 0) return compared;

  compared = compareNumber(
    left.source.instructionAddress,
    right.source.instructionAddress,
  );
  if (compared !== 0) return compared;

  compared = compareNumber(
    MODE_ORDER[left.source.mode],
    MODE_ORDER[right.source.mode],
  );
  if (compared !== 0) return compared;

  compared = compareNumber(
    REFERENCE_KIND_ORDER[left.kind],
    REFERENCE_KIND_ORDER[right.kind],
  );
  if (compared !== 0) return compared;

  compared = compareNumber(left.target.runtimeAddress, right.target.runtimeAddress);
  if (compared !== 0) return compared;

  return compareNumber(
    targetModeOrder(left.target.mode),
    targetModeOrder(right.target.mode),
  );
}
