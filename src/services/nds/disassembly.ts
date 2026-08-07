import {
  DisassemblyBackendError,
  type ArmDisassemblyBackend,
  type ArmMode,
  type DecodedArmInstruction,
} from "../disassembly/backend.js";
import { NdsError } from "./errors.js";
import type { NdsProcessor } from "./overlays.js";
import {
  codeSourceAt,
  resolveNdsCodeSource,
  resolveNdsControlFlowTarget,
  withValidatedNdsRomReader,
  type NdsCodeSource,
  type NdsCodeSourceResolution,
  type NdsDisassemblyLocation,
} from "./disassembly-source.js";
import type { NdsRomMap } from "./rom-map.js";

const UINT32_MAX = 0xffffffff;

export type StaticFlowKind =
  | "fallthrough"
  | "conditional-branch"
  | "unconditional-branch"
  | "call"
  | "return"
  | "indirect-branch"
  | "indirect-call";

export interface StaticInstruction {
  readonly address: number;
  readonly romOffset: number;
  readonly size: 2 | 4;
  readonly bytesHex: string;
  readonly mode: ArmMode;
  readonly mnemonic: string;
  readonly operands: string;
  readonly flow: {
    readonly kind: StaticFlowKind;
    readonly directTarget: number | null;
    readonly targetMode: ArmMode | null;
    readonly fallthrough: number | null;
  };
  readonly source: {
    readonly processor: NdsProcessor;
    readonly component: "main" | "overlay";
    readonly overlayId: number | null;
  };
  readonly targetResolution: NdsCodeSourceResolution | null;
}

export interface DetailedStaticInstruction {
  readonly instruction: StaticInstruction;
  readonly decoded: DecodedArmInstruction;
}

export interface LinearDisassemblyOptions {
  readonly maxInstructions: number;
  readonly maxBytes: number;
}

export type LinearDisassemblyResult =
  | Exclude<NdsCodeSourceResolution, { readonly status: "resolved" }>
  | {
      readonly status: "complete" | "decode-stopped" | "component-boundary";
      readonly source: NdsCodeSource;
      readonly instructions: readonly StaticInstruction[];
      readonly decodedBytes: number;
      readonly stopAddress: number;
    };

export type DetailedLinearDisassemblyResult =
  | Exclude<NdsCodeSourceResolution, { readonly status: "resolved" }>
  | {
      readonly status: "complete" | "decode-stopped" | "component-boundary";
      readonly source: NdsCodeSource;
      readonly instructions: readonly DetailedStaticInstruction[];
      readonly decodedBytes: number;
      readonly stopAddress: number;
    };

function firstImmediate(decoded: DecodedArmInstruction): number | null {
  for (const operand of decoded.operands) {
    if (operand.kind === "immediate") {
      return operand.value >>> 0;
    }
  }
  return null;
}

function isLinkRegisterReturn(decoded: DecodedArmInstruction): boolean {
  return decoded.mnemonic.toLowerCase() === "bx"
    && decoded.operands.some(
      (operand) => operand.kind === "register" && operand.name === "lr",
    );
}

function opposite(mode: ArmMode): ArmMode {
  return mode === "arm" ? "thumb" : "arm";
}

function fallthroughAddress(decoded: DecodedArmInstruction): number | null {
  const next = decoded.address + decoded.size;
  return next <= UINT32_MAX ? next : null;
}

function normalizeFlow(
  decoded: DecodedArmInstruction,
  mode: ArmMode,
): StaticInstruction["flow"] {
  const next = fallthroughAddress(decoded);
  const immediate = firstImmediate(decoded);

  if (decoded.isReturn || isLinkRegisterReturn(decoded)) {
    return {
      kind: "return",
      directTarget: null,
      targetMode: null,
      fallthrough: null,
    };
  }

  if (decoded.isCall) {
    return {
      kind: immediate === null ? "indirect-call" : "call",
      directTarget: immediate,
      targetMode: immediate === null
        ? null
        : decoded.switchesMode
          ? opposite(mode)
          : mode,
      fallthrough: next,
    };
  }

  if (decoded.isJump) {
    if (immediate === null) {
      return {
        kind: "indirect-branch",
        directTarget: null,
        targetMode: null,
        fallthrough: null,
      };
    }
    return {
      kind: decoded.isConditional
        ? "conditional-branch"
        : "unconditional-branch",
      directTarget: immediate,
      targetMode: decoded.switchesMode ? opposite(mode) : mode,
      fallthrough: decoded.isConditional ? next : null,
    };
  }

  return {
    kind: "fallthrough",
    directTarget: null,
    targetMode: null,
    fallthrough: next,
  };
}

export function decodeNdsInstructionDetailed(
  map: NdsRomMap,
  source: NdsCodeSource,
  bytes: Uint8Array,
  backend: ArmDisassemblyBackend,
): DetailedStaticInstruction | null {
  const decoded = backend.decodeOne(bytes, source.runtimeAddress, source.mode);
  if (decoded === null) {
    return null;
  }
  if (decoded.address !== source.runtimeAddress) {
    throw new DisassemblyBackendError(
      `Decoder returned address 0x${decoded.address.toString(16)} for requested address 0x${source.runtimeAddress.toString(16)}`,
    );
  }
  if (decoded.size > bytes.length) {
    throw new DisassemblyBackendError(
      `Decoder reported ${decoded.size} bytes from a ${bytes.length}-byte input window`,
    );
  }

  const flow = normalizeFlow(decoded, source.mode);
  const targetResolution = flow.directTarget !== null && flow.targetMode !== null
    ? resolveNdsControlFlowTarget(
      map,
      source,
      flow.directTarget,
      flow.targetMode,
    )
    : null;

  return {
    instruction: {
      address: source.runtimeAddress,
      romOffset: source.romOffset,
      size: decoded.size,
      bytesHex: Buffer.from(bytes.subarray(0, decoded.size)).toString("hex"),
      mode: source.mode,
      mnemonic: decoded.mnemonic,
      operands: decoded.operandsText,
      flow,
      source: {
        processor: source.processor,
        component: source.component,
        overlayId: source.overlayId,
      },
      targetResolution,
    },
    decoded,
  };
}

export function decodeNdsInstruction(
  map: NdsRomMap,
  source: NdsCodeSource,
  bytes: Uint8Array,
  backend: ArmDisassemblyBackend,
): StaticInstruction | null {
  return decodeNdsInstructionDetailed(map, source, bytes, backend)?.instruction ?? null;
}

function requirePositiveSafeInteger(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new NdsError(
      "range-out-of-bounds",
      `${label} must be a positive safe integer`,
    );
  }
}

function stoppedDetailedResult(
  status: "complete" | "decode-stopped" | "component-boundary",
  source: NdsCodeSource,
  instructions: readonly DetailedStaticInstruction[],
  decodedBytes: number,
): Extract<DetailedLinearDisassemblyResult, { readonly status: "complete" | "decode-stopped" | "component-boundary" }> {
  return {
    status,
    source,
    instructions,
    decodedBytes,
    stopAddress: source.runtimeAddress + decodedBytes,
  };
}

export async function disassembleNdsRangeDetailed(
  map: NdsRomMap,
  location: NdsDisassemblyLocation,
  options: LinearDisassemblyOptions,
  backend: ArmDisassemblyBackend,
): Promise<DetailedLinearDisassemblyResult> {
  requirePositiveSafeInteger(options.maxInstructions, "Maximum instruction count");
  requirePositiveSafeInteger(options.maxBytes, "Maximum source byte count");

  const resolved = resolveNdsCodeSource(map, location);
  if (resolved.status !== "resolved") {
    return resolved;
  }

  return await withValidatedNdsRomReader(map, async (read) => {
    const start = resolved.source;
    const bytes = await read(start, options.maxBytes);
    const instructions: DetailedStaticInstruction[] = [];
    let cursor = 0;

    while (
      instructions.length < options.maxInstructions
      && cursor < bytes.length
    ) {
      const remaining = bytes.length - cursor;
      const minimumSize = start.mode === "arm" ? 4 : 2;
      if (remaining < minimumSize) {
        const reachedBoundary = start.romOffset + bytes.length >= start.romEnd;
        return stoppedDetailedResult(
          reachedBoundary ? "component-boundary" : "complete",
          start,
          instructions,
          cursor,
        );
      }

      const source = codeSourceAt(start, start.runtimeAddress + cursor);
      const detailed = decodeNdsInstructionDetailed(
        map,
        source,
        bytes.subarray(cursor),
        backend,
      );
      if (detailed === null) {
        return stoppedDetailedResult(
          "decode-stopped",
          start,
          instructions,
          cursor,
        );
      }

      const instruction = detailed.instruction;
      const crossesReadWindow = cursor + instruction.size > bytes.length;
      const crossesComponent = source.romOffset + instruction.size > source.romEnd;
      if (crossesReadWindow || crossesComponent) {
        return stoppedDetailedResult(
          crossesComponent || start.romOffset + bytes.length >= start.romEnd
            ? "component-boundary"
            : "complete",
          start,
          instructions,
          cursor,
        );
      }

      instructions.push(detailed);
      cursor += instruction.size;
    }

    const reachedBoundary = start.romOffset + cursor >= start.romEnd;
    return stoppedDetailedResult(
      reachedBoundary ? "component-boundary" : "complete",
      start,
      instructions,
      cursor,
    );
  });
}

export async function disassembleNdsRange(
  map: NdsRomMap,
  location: NdsDisassemblyLocation,
  options: LinearDisassemblyOptions,
  backend: ArmDisassemblyBackend,
): Promise<LinearDisassemblyResult> {
  const result = await disassembleNdsRangeDetailed(
    map,
    location,
    options,
    backend,
  );
  if (!("instructions" in result)) {
    return result;
  }
  return {
    ...result,
    instructions: result.instructions.map((entry) => entry.instruction),
  };
}
