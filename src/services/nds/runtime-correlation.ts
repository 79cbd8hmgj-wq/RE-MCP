import type { ArmDisassemblyBackend } from "../disassembly/backend.js";
import type { StopContext } from "../stop-context.js";
import {
  NdsError,
  type NdsRuntimeCorrelationErrorCategory,
} from "./errors.js";
import { hashFileSha256 } from "./io.js";
import {
  resolveRuntimeAddress,
  type RuntimeCandidate,
  type RuntimeResolution,
} from "./resolver.js";
import { readNdsRomMap } from "./rom-map.js";

export interface NdsRuntimeCorrelationOptions {
  readonly nearbyInstructions: number;
  readonly referenceLimit: number;
  readonly maxOutputBytes: number;
  readonly includeGhidra: boolean;
  readonly decompileGhidraFunction: boolean;
}

export interface NdsRuntimeCorrelationInput {
  readonly romPath: string;
  readonly romDisplayPath: string;
  readonly expectedRomSha256: string;
  readonly stopContext: StopContext;
  readonly options: NdsRuntimeCorrelationOptions;
}

export type NdsRuntimeStaticCorrelation =
  | { readonly status: "runtime-only"; readonly reason: string }
  | { readonly status: "not-decodable"; readonly reason: string };

export type NdsRuntimeGhidraCorrelation = {
  readonly status: "not-requested";
};

export interface NdsRuntimeCandidateCorrelation {
  readonly canonical: RuntimeCandidate;
  readonly static: NdsRuntimeStaticCorrelation;
  readonly ghidraDerived: NdsRuntimeGhidraCorrelation;
}

export interface NdsRuntimeCorrelationResult {
  readonly runtimeObserved: {
    readonly capturedAt: string;
    readonly pc: number;
    readonly sp: number;
    readonly lr: number;
    readonly cpsr: number;
    readonly mode: "arm" | "thumb";
    readonly stop: StopContext["stop"];
    readonly breakpoint: NonNullable<StopContext["breakpoint"]> | null;
  };
  readonly rom: {
    readonly path: string;
    readonly sha256: string;
    readonly launchSha256: string;
    readonly identityMatched: true;
  };
  readonly canonical: {
    readonly processor: "arm9";
    readonly status: "resolved" | "ambiguous" | "unmapped";
    readonly candidateCount: number;
  };
  readonly candidates: readonly NdsRuntimeCandidateCorrelation[];
}

function correlationError(
  category: NdsRuntimeCorrelationErrorCategory,
  message: string,
): NdsError<NdsRuntimeCorrelationErrorCategory> {
  return new NdsError(category, message);
}

function candidatesForResolution(resolution: RuntimeResolution): RuntimeCandidate[] {
  if (resolution.status === "unmapped") {
    return [];
  }
  if (resolution.status === "ambiguous-runtime-address") {
    return [...resolution.candidates].sort((left, right) =>
      (left.overlayId ?? -1) - (right.overlayId ?? -1),
    );
  }
  return [resolution.candidate];
}

function canonicalStatus(
  resolution: RuntimeResolution,
): NdsRuntimeCorrelationResult["canonical"]["status"] {
  if (resolution.status === "unmapped") return "unmapped";
  if (resolution.status === "ambiguous-runtime-address") return "ambiguous";
  return "resolved";
}

function initialStatic(candidate: RuntimeCandidate): NdsRuntimeStaticCorrelation {
  if (candidate.representation === "runtime-only") {
    return {
      status: "runtime-only",
      reason: "Canonical runtime candidate has no initialized executable bytes",
    };
  }
  return {
    status: "not-decodable",
    reason: "Static evidence has not been attached to this correlation result",
  };
}

export async function correlateNdsStopContext(
  input: NdsRuntimeCorrelationInput,
  _backend: ArmDisassemblyBackend,
): Promise<NdsRuntimeCorrelationResult> {
  const map = await readNdsRomMap(input.romPath);
  if (map.sha256 !== input.expectedRomSha256) {
    throw correlationError(
      "runtime-correlation-rom-identity-mismatch",
      "Current ROM SHA-256 does not match the launch-time ROM SHA-256",
    );
  }

  const resolution = resolveRuntimeAddress(
    map,
    input.stopContext.registers.pc,
    "arm9",
  );
  const candidates = candidatesForResolution(resolution);
  const result: NdsRuntimeCorrelationResult = {
    runtimeObserved: {
      capturedAt: input.stopContext.capturedAt,
      pc: input.stopContext.registers.pc,
      sp: input.stopContext.registers.sp,
      lr: input.stopContext.registers.lr,
      cpsr: input.stopContext.registers.cpsr,
      mode: input.stopContext.registers.mode,
      stop: input.stopContext.stop,
      breakpoint: input.stopContext.breakpoint ?? null,
    },
    rom: {
      path: input.romDisplayPath,
      sha256: map.sha256,
      launchSha256: input.expectedRomSha256,
      identityMatched: true,
    },
    canonical: {
      processor: "arm9",
      status: canonicalStatus(resolution),
      candidateCount: candidates.length,
    },
    candidates: candidates.map((candidate) => ({
      canonical: candidate,
      static: initialStatic(candidate),
      ghidraDerived: { status: "not-requested" },
    })),
  };

  const finalSha256 = await hashFileSha256(input.romPath);
  if (finalSha256 !== input.expectedRomSha256) {
    throw correlationError(
      "runtime-correlation-rom-identity-mismatch",
      "Source ROM changed during runtime correlation",
    );
  }

  if (Buffer.byteLength(JSON.stringify(result), "utf8") > input.options.maxOutputBytes) {
    throw correlationError(
      "runtime-correlation-output-limit",
      "Runtime correlation result exceeds configured output limit",
    );
  }

  return result;
}
