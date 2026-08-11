import type { ArmDisassemblyBackend, ArmMode } from "../disassembly/backend.js";
import { disassembleNdsRange, type StaticInstruction } from "../nds/disassembly.js";
import { resolveNdsCodeSource } from "../nds/disassembly-source.js";
import type { NdsProcessor } from "../nds/overlays.js";
import type { NdsRomMap } from "../nds/rom-map.js";

export interface ReContextWindowLocation {
  readonly processor: NdsProcessor;
  readonly runtimeAddress: number;
  readonly mode: ArmMode;
  readonly overlayId?: number;
}

export interface ReContextWindowLimits {
  readonly maxInstructions: number;
  readonly maxBytes: number;
}

export interface ReContextWindowResult {
  readonly instructions: readonly StaticInstruction[];
  readonly backwardDecodeAmbiguous: boolean;
}

function candidateStarts(
  runtimeStart: number,
  anchor: number,
  mode: ArmMode,
  maxInstructions: number,
  maxBytes: number,
): readonly number[] {
  const desiredBefore = Math.max(0, Math.ceil((maxInstructions - 1) / 2));
  if (desiredBefore === 0 || anchor <= runtimeStart) return [anchor];

  if (mode === "arm") {
    const availableWords = Math.floor((anchor - runtimeStart) / 4);
    const byteWords = Math.floor(Math.max(0, maxBytes - 4) / 4);
    const before = Math.min(desiredBefore, availableWords, byteWords);
    return [anchor - before * 4, anchor];
  }

  const maximumBackBytes = Math.min(
    anchor - runtimeStart,
    Math.max(0, maxBytes - 2),
    desiredBefore * 4,
  );
  const starts: number[] = [anchor];
  for (let delta = 2; delta <= maximumBackBytes; delta += 2) {
    starts.push(anchor - delta);
  }
  return starts.sort((left, right) => left - right);
}

function containsAnchor(
  instructions: readonly StaticInstruction[],
  anchor: number,
): boolean {
  return instructions.some((instruction) => instruction.address === anchor);
}

function precedingKey(
  instructions: readonly StaticInstruction[],
  anchor: number,
): string {
  return instructions
    .filter((instruction) => instruction.address < anchor)
    .map((instruction) => `${instruction.address.toString(16)}:${instruction.bytesHex}`)
    .join("|");
}

export async function disassembleReContextWindow(
  map: NdsRomMap,
  location: ReContextWindowLocation,
  limits: ReContextWindowLimits,
  backend: ArmDisassemblyBackend,
): Promise<ReContextWindowResult> {
  const resolved = resolveNdsCodeSource(map, location);
  if (resolved.status !== "resolved") {
    return { instructions: [], backwardDecodeAmbiguous: false };
  }

  const starts = candidateStarts(
    resolved.source.runtimeStart,
    location.runtimeAddress,
    location.mode,
    limits.maxInstructions,
    limits.maxBytes,
  );
  const candidates: Array<readonly StaticInstruction[]> = [];

  for (const start of starts) {
    const result = await disassembleNdsRange(
      map,
      {
        processor: location.processor,
        runtimeAddress: start,
        mode: location.mode,
        ...(location.overlayId === undefined ? {} : { overlayId: location.overlayId }),
      },
      limits,
      backend,
    );
    if ("instructions" in result && containsAnchor(result.instructions, location.runtimeAddress)) {
      candidates.push(result.instructions);
    }
  }

  if (candidates.length === 0) {
    return { instructions: [], backwardDecodeAmbiguous: false };
  }

  candidates.sort((left, right) => {
    const leftBefore = left.filter((instruction) => instruction.address < location.runtimeAddress).length;
    const rightBefore = right.filter((instruction) => instruction.address < location.runtimeAddress).length;
    if (leftBefore !== rightBefore) return rightBefore - leftBefore;
    return (left[0]?.address ?? location.runtimeAddress) - (right[0]?.address ?? location.runtimeAddress);
  });

  const distinctPredecessors = new Set(
    candidates.map((candidate) => precedingKey(candidate, location.runtimeAddress)),
  );
  return {
    instructions: candidates[0] ?? [],
    backwardDecodeAmbiguous: location.mode === "thumb" && distinctPredecessors.size > 1,
  };
}
