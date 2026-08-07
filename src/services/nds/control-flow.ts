import type {
  ArmDisassemblyBackend,
  ArmMode,
} from "../disassembly/backend.js";
import {
  decodeNdsInstruction,
  type StaticInstruction,
} from "./disassembly.js";
import {
  codeSourceAt,
  resolveNdsCodeSource,
  withValidatedNdsRomReader,
  type NdsCodeSource,
  type NdsCodeSourceResolution,
  type NdsDisassemblyLocation,
} from "./disassembly-source.js";
import { NdsError } from "./errors.js";
import type { NdsRomMap } from "./rom-map.js";

export interface ControlFlowLimits {
  readonly maxBlocks: number;
  readonly maxInstructions: number;
  readonly maxBytes: number;
  readonly maxEdges: number;
}

export interface StaticBasicBlock {
  readonly id: string;
  readonly source: NdsCodeSource;
  readonly startAddress: number;
  readonly mode: ArmMode;
  readonly instructions: readonly StaticInstruction[];
  readonly stopReason:
    | "branch"
    | "return"
    | "indirect"
    | "decode-stopped"
    | "component-boundary"
    | "limit";
}

export interface StaticControlFlowEdge {
  readonly fromBlockId: string;
  readonly type:
    | "fallthrough"
    | "branch"
    | "conditional-taken"
    | "conditional-fallthrough";
  readonly targetAddress: number;
  readonly targetMode: ArmMode;
  readonly targetBlockId: string | null;
}

export interface StaticCallEdge {
  readonly fromBlockId: string;
  readonly instructionAddress: number;
  readonly targetAddress: number | null;
  readonly targetMode: ArmMode | null;
  readonly resolution: NdsCodeSourceResolution | null;
}

export interface StaticUnresolvedEdge {
  readonly fromBlockId: string;
  readonly instructionAddress: number;
  readonly kind:
    | "indirect-branch"
    | "indirect-call"
    | "return"
    | "ambiguous-code-source"
    | "compressed-overlay-not-decodable"
    | "runtime-only-bss"
    | "unmapped-address";
}

export interface StaticControlFlowGraph {
  readonly entry: NdsCodeSource;
  readonly status: "complete" | "truncated";
  readonly truncationReasons: readonly (
    | "block-limit"
    | "instruction-limit"
    | "byte-limit"
    | "edge-limit"
  )[];
  readonly blocks: readonly StaticBasicBlock[];
  readonly edges: readonly StaticControlFlowEdge[];
  readonly calls: readonly StaticCallEdge[];
  readonly unresolvedEdges: readonly StaticUnresolvedEdge[];
  readonly totals: {
    readonly blocks: number;
    readonly instructions: number;
    readonly bytes: number;
    readonly edges: number;
  };
}

export type ControlFlowResult =
  | Exclude<NdsCodeSourceResolution, { readonly status: "resolved" }>
  | StaticControlFlowGraph;

type TruncationReason = StaticControlFlowGraph["truncationReasons"][number];
type TraversalEdgeType = StaticControlFlowEdge["type"];

const TRUNCATION_REASON_ORDER: readonly TruncationReason[] = [
  "block-limit",
  "instruction-limit",
  "byte-limit",
  "edge-limit",
];

function requirePositiveSafeInteger(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new NdsError(
      "range-out-of-bounds",
      `${label} must be a positive safe integer`,
    );
  }
}

function validateLimits(limits: ControlFlowLimits): void {
  requirePositiveSafeInteger(limits.maxBlocks, "Maximum block count");
  requirePositiveSafeInteger(
    limits.maxInstructions,
    "Maximum instruction count",
  );
  requirePositiveSafeInteger(limits.maxBytes, "Maximum decoded byte count");
  requirePositiveSafeInteger(limits.maxEdges, "Maximum traversal edge count");
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

function unresolvedKind(
  resolution: Exclude<NdsCodeSourceResolution, { readonly status: "resolved" }>,
): StaticUnresolvedEdge["kind"] {
  switch (resolution.status) {
    case "ambiguous-code-source":
    case "compressed-overlay-not-decodable":
    case "runtime-only-bss":
    case "unmapped-address":
      return resolution.status;
    case "mode-ambiguous":
      throw new NdsError(
        "range-out-of-bounds",
        "CFG target unexpectedly lacked a propagated ARM/Thumb mode",
      );
  }
}

function sameComponentResolution(
  source: NdsCodeSource,
  runtimeAddress: number,
  mode: ArmMode,
): NdsCodeSourceResolution | null {
  if (
    runtimeAddress < source.runtimeStart
    || runtimeAddress >= source.runtimeEnd
  ) {
    return null;
  }
  return {
    status: "resolved",
    source: {
      ...codeSourceAt(source, runtimeAddress),
      mode,
    },
  };
}

export async function analyzeNdsControlFlow(
  map: NdsRomMap,
  location: NdsDisassemblyLocation,
  limits: ControlFlowLimits,
  backend: ArmDisassemblyBackend,
): Promise<ControlFlowResult> {
  validateLimits(limits);
  const entryResolution = resolveNdsCodeSource(map, location);
  if (entryResolution.status !== "resolved") {
    return entryResolution;
  }

  return await withValidatedNdsRomReader(map, async (read) => {
    const entry = entryResolution.source;
    const queue: NdsCodeSource[] = [entry];
    const scheduled = new Set<string>([blockKey(entry)]);
    const visited = new Set<string>();
    const blocks: StaticBasicBlock[] = [];
    const edges: StaticControlFlowEdge[] = [];
    const calls: StaticCallEdge[] = [];
    const unresolvedEdges: StaticUnresolvedEdge[] = [];
    const reasons = new Set<TruncationReason>();
    let totalInstructions = 0;
    let totalBytes = 0;
    let totalEdges = 0;

    function scheduleTarget(
      resolution: NdsCodeSourceResolution,
    ): string | null {
      if (resolution.status !== "resolved") {
        return null;
      }
      const id = blockKey(resolution.source);
      if (scheduled.has(id)) {
        return id;
      }
      if (scheduled.size >= limits.maxBlocks) {
        reasons.add("block-limit");
        return null;
      }
      scheduled.add(id);
      queue.push(resolution.source);
      return id;
    }

    function addTraversalEdge(input: {
      readonly fromBlockId: string;
      readonly instructionAddress: number;
      readonly type: TraversalEdgeType;
      readonly targetAddress: number;
      readonly targetMode: ArmMode;
      readonly resolution: NdsCodeSourceResolution;
    }): void {
      if (totalEdges >= limits.maxEdges) {
        reasons.add("edge-limit");
        return;
      }

      let targetBlockId: string | null = null;
      if (input.resolution.status === "resolved") {
        targetBlockId = scheduleTarget(input.resolution);
      } else {
        unresolvedEdges.push({
          fromBlockId: input.fromBlockId,
          instructionAddress: input.instructionAddress,
          kind: unresolvedKind(input.resolution),
        });
      }

      edges.push({
        fromBlockId: input.fromBlockId,
        type: input.type,
        targetAddress: input.targetAddress,
        targetMode: input.targetMode,
        targetBlockId,
      });
      totalEdges += 1;
    }

    while (queue.length > 0) {
      const blockSource = queue.shift();
      if (blockSource === undefined) {
        break;
      }
      const id = blockKey(blockSource);
      if (visited.has(id)) {
        continue;
      }
      visited.add(id);

      const instructions: StaticInstruction[] = [];
      let stopReason: StaticBasicBlock["stopReason"] = "component-boundary";
      let cursor = 0;
      const remainingByteBudget = limits.maxBytes - totalBytes;
      const bytes = remainingByteBudget > 0
        ? await read(blockSource, remainingByteBudget)
        : Buffer.alloc(0);

      while (true) {
        const currentAddress = blockSource.runtimeAddress + cursor;
        const currentRomOffset = blockSource.romOffset + cursor;
        if (
          currentAddress >= blockSource.runtimeEnd
          || currentRomOffset >= blockSource.romEnd
        ) {
          stopReason = "component-boundary";
          break;
        }

        let hitLimit = false;
        if (totalInstructions >= limits.maxInstructions) {
          reasons.add("instruction-limit");
          hitLimit = true;
        }
        if (totalBytes >= limits.maxBytes) {
          reasons.add("byte-limit");
          hitLimit = true;
        }
        if (hitLimit) {
          stopReason = "limit";
          break;
        }

        const remainingWindow = bytes.length - cursor;
        const minimumInstructionSize = blockSource.mode === "arm" ? 4 : 2;
        if (remainingWindow < minimumInstructionSize) {
          const reachesComponentEnd = currentRomOffset + remainingWindow
            >= blockSource.romEnd;
          if (reachesComponentEnd) {
            stopReason = "component-boundary";
          } else {
            reasons.add("byte-limit");
            stopReason = "limit";
          }
          break;
        }

        const currentSource = codeSourceAt(blockSource, currentAddress);
        const instruction = decodeNdsInstruction(
          map,
          currentSource,
          bytes.subarray(cursor),
          backend,
        );
        if (instruction === null) {
          stopReason = "decode-stopped";
          break;
        }
        if (totalBytes + instruction.size > limits.maxBytes) {
          reasons.add("byte-limit");
          stopReason = "limit";
          break;
        }

        instructions.push(instruction);
        totalInstructions += 1;
        totalBytes += instruction.size;
        cursor += instruction.size;

        const nextAddress = instruction.address + instruction.size;
        const nextInsideComponent = nextAddress < blockSource.runtimeEnd
          && blockSource.romOffset + cursor < blockSource.romEnd;

        switch (instruction.flow.kind) {
          case "fallthrough": {
            if (!nextInsideComponent) {
              stopReason = "component-boundary";
              break;
            }
            continue;
          }
          case "call": {
            calls.push({
              fromBlockId: id,
              instructionAddress: instruction.address,
              targetAddress: instruction.flow.directTarget,
              targetMode: instruction.flow.targetMode,
              resolution: instruction.targetResolution,
            });
            if (!nextInsideComponent || instruction.flow.fallthrough === null) {
              stopReason = "component-boundary";
              break;
            }
            continue;
          }
          case "indirect-call": {
            calls.push({
              fromBlockId: id,
              instructionAddress: instruction.address,
              targetAddress: null,
              targetMode: null,
              resolution: null,
            });
            unresolvedEdges.push({
              fromBlockId: id,
              instructionAddress: instruction.address,
              kind: "indirect-call",
            });
            if (!nextInsideComponent || instruction.flow.fallthrough === null) {
              stopReason = "component-boundary";
              break;
            }
            continue;
          }
          case "return": {
            unresolvedEdges.push({
              fromBlockId: id,
              instructionAddress: instruction.address,
              kind: "return",
            });
            stopReason = "return";
            break;
          }
          case "indirect-branch": {
            unresolvedEdges.push({
              fromBlockId: id,
              instructionAddress: instruction.address,
              kind: "indirect-branch",
            });
            stopReason = "indirect";
            break;
          }
          case "unconditional-branch": {
            if (
              instruction.flow.directTarget === null
              || instruction.flow.targetMode === null
              || instruction.targetResolution === null
            ) {
              throw new NdsError(
                "range-out-of-bounds",
                "Direct branch lacks canonical target metadata",
              );
            }
            addTraversalEdge({
              fromBlockId: id,
              instructionAddress: instruction.address,
              type: "branch",
              targetAddress: instruction.flow.directTarget,
              targetMode: instruction.flow.targetMode,
              resolution: instruction.targetResolution,
            });
            stopReason = "branch";
            break;
          }
          case "conditional-branch": {
            if (
              instruction.flow.directTarget === null
              || instruction.flow.targetMode === null
              || instruction.targetResolution === null
            ) {
              throw new NdsError(
                "range-out-of-bounds",
                "Conditional branch lacks canonical target metadata",
              );
            }
            addTraversalEdge({
              fromBlockId: id,
              instructionAddress: instruction.address,
              type: "conditional-taken",
              targetAddress: instruction.flow.directTarget,
              targetMode: instruction.flow.targetMode,
              resolution: instruction.targetResolution,
            });

            const fallthrough = instruction.flow.fallthrough;
            if (fallthrough !== null) {
              const fallthroughResolution = sameComponentResolution(
                blockSource,
                fallthrough,
                instruction.mode,
              );
              if (fallthroughResolution !== null) {
                addTraversalEdge({
                  fromBlockId: id,
                  instructionAddress: instruction.address,
                  type: "conditional-fallthrough",
                  targetAddress: fallthrough,
                  targetMode: instruction.mode,
                  resolution: fallthroughResolution,
                });
              }
            }
            stopReason = "branch";
            break;
          }
        }

        break;
      }

      blocks.push({
        id,
        source: blockSource,
        startAddress: blockSource.runtimeAddress,
        mode: blockSource.mode,
        instructions,
        stopReason,
      });
    }

    const truncationReasons = TRUNCATION_REASON_ORDER.filter(
      (reason) => reasons.has(reason),
    );
    return {
      entry,
      status: truncationReasons.length === 0 ? "complete" : "truncated",
      truncationReasons,
      blocks,
      edges,
      calls,
      unresolvedEdges,
      totals: {
        blocks: blocks.length,
        instructions: totalInstructions,
        bytes: totalBytes,
        edges: totalEdges,
      },
    };
  });
}
