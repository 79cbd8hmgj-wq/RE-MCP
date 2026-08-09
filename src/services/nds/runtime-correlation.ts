import type { ArmDisassemblyBackend } from "../disassembly/backend.js";
import type { StopContext } from "../stop-context.js";
import {
  disassembleNdsRange,
  type StaticInstruction,
} from "./disassembly.js";
import {
  NdsError,
  type NdsRuntimeCorrelationErrorCategory,
} from "./errors.js";
import {
  analyzeNdsFunction,
  type AnalyzeFunctionProofStatus,
} from "./function-analysis.js";
import type { FunctionProof } from "./function-model.js";
import { hashFileSha256 } from "./io.js";
import { listNdsReferences } from "./reference-list.js";
import type { StaticReference } from "./references.js";
import {
  resolveRuntimeAddress,
  type RuntimeCandidate,
  type RuntimeResolution,
} from "./resolver.js";
import { readNdsRomMap, type NdsRomMap } from "./rom-map.js";

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
  | {
      readonly status: "available";
      readonly instructions: readonly StaticInstruction[];
      readonly references: readonly StaticReference[];
      readonly functionEntry: {
        readonly proofStatus: AnalyzeFunctionProofStatus;
        readonly runtimeMode: "arm" | "thumb";
        readonly staticMode: "arm" | "thumb";
        readonly modeConsistent: boolean;
        readonly evidence: readonly FunctionProof[];
      };
    }
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

const FUNCTION_PROOF_LIMITS = {
  proof: {
    maxComponents: 32,
    maxBlocks: 128,
    maxInstructions: 2048,
    maxBytes: 8192,
    maxEdges: 512,
    maxXrefs: 256,
  },
  cfg: {
    maxBlocks: 64,
    maxInstructions: 512,
    maxBytes: 2048,
    maxEdges: 128,
  },
} as const;

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

async function correlateStaticCandidate(
  map: NdsRomMap,
  candidate: RuntimeCandidate,
  input: NdsRuntimeCorrelationInput,
  backend: ArmDisassemblyBackend,
): Promise<NdsRuntimeStaticCorrelation> {
  if (candidate.representation === "runtime-only") {
    return {
      status: "runtime-only",
      reason: "Canonical runtime candidate has no initialized executable bytes",
    };
  }

  const runtimeMode = input.stopContext.registers.mode;
  const location = {
    processor: "arm9" as const,
    runtimeAddress: candidate.runtimeAddress,
    mode: runtimeMode,
    ...(candidate.overlayId === null ? {} : { overlayId: candidate.overlayId }),
  };
  const maxBytes = Math.min(128, input.options.nearbyInstructions * 4);
  const disassembly = await disassembleNdsRange(
    map,
    location,
    {
      maxInstructions: input.options.nearbyInstructions,
      maxBytes,
    },
    backend,
  );
  if (!("instructions" in disassembly) || disassembly.instructions.length === 0) {
    return {
      status: "not-decodable",
      reason: disassembly.status,
    };
  }

  let references: readonly StaticReference[] = [];
  if (input.options.referenceLimit > 0) {
    const listed = await listNdsReferences(
      map,
      location,
      {
        maxInstructions: input.options.nearbyInstructions,
        maxBytes,
      },
      backend,
    );
    if ("references" in listed) {
      references = listed.references.slice(0, input.options.referenceLimit);
    }
  }

  const functionAnalysis = await analyzeNdsFunction(
    map,
    {
      processor: "arm9",
      runtimeAddress: candidate.runtimeAddress,
      mode: runtimeMode,
      ...(candidate.overlayId === null ? {} : { overlayId: candidate.overlayId }),
      proofScope: { kind: "all-executable-components" },
      seeds: [],
    },
    FUNCTION_PROOF_LIMITS,
    backend,
  );

  return {
    status: "available",
    instructions: disassembly.instructions,
    references,
    functionEntry: {
      proofStatus: functionAnalysis.proofStatus,
      runtimeMode,
      staticMode: functionAnalysis.entry.mode,
      modeConsistent: functionAnalysis.entry.mode === runtimeMode,
      evidence: functionAnalysis.evidence,
    },
  };
}

export async function correlateNdsStopContext(
  input: NdsRuntimeCorrelationInput,
  backend: ArmDisassemblyBackend,
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
  const correlatedCandidates: NdsRuntimeCandidateCorrelation[] = [];
  for (const candidate of candidates) {
    correlatedCandidates.push({
      canonical: candidate,
      static: await correlateStaticCandidate(map, candidate, input, backend),
      ghidraDerived: { status: "not-requested" },
    });
  }

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
    candidates: correlatedCandidates,
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
