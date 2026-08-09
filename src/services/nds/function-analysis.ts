import type {
  ArmDisassemblyBackend,
  ArmMode,
} from "../disassembly/backend.js";
import {
  analyzeNdsControlFlowWithReader,
  type ControlFlowLimits,
  type StaticCallEdge,
  type StaticControlFlowGraph,
  type StaticUnresolvedEdge,
} from "./control-flow.js";
import {
  resolveNdsCodeSource,
  resolveNdsControlFlowTarget,
  withValidatedNdsCodeReader,
  type NdsCodeSource,
} from "./disassembly-source.js";
import {
  NdsError,
  type AnyNdsErrorCategory,
  type NdsFunctionErrorCategory,
} from "./errors.js";
import {
  compareFunctionProof,
  provenFunctionId,
  type FunctionProof,
  type ProvenFunctionIdentity,
} from "./function-model.js";
import {
  prepareFunctionSearch,
  type FunctionSearchScope,
  type FunctionSearchSeed,
} from "./function-source.js";
import type { NdsProcessor } from "./overlays.js";
import type { StaticReference } from "./references.js";
import type { NdsRomMap } from "./rom-map.js";
import type {
  ReferenceSearchScope,
  ReferenceSearchSeed,
} from "./xref-source.js";
import {
  findNdsXrefsWithReader,
  type ReferenceComponentCoverage,
  type ReferenceScanLimits,
} from "./xrefs.js";

export interface AnalyzeNdsFunctionRequest {
  readonly processor: NdsProcessor;
  readonly runtimeAddress: number;
  readonly mode: ArmMode;
  readonly overlayId?: number | undefined;
  readonly proofScope: FunctionSearchScope;
  readonly seeds: readonly FunctionSearchSeed[];
}

export interface AnalyzeFunctionLimits {
  readonly proof: ReferenceScanLimits;
  readonly cfg: ControlFlowLimits;
}

export type AnalyzeFunctionProofStatus =
  | "proven"
  | "not-proven-function-entry"
  | "proof-inconclusive";

export interface AnalyzeNdsFunctionResult {
  readonly proofStatus: AnalyzeFunctionProofStatus;
  readonly entry: ProvenFunctionIdentity;
  readonly evidence: readonly FunctionProof[];
  readonly proofSearch: {
    readonly status: "complete" | "partial-coverage" | "truncated";
    readonly coverage: readonly ReferenceComponentCoverage[];
    readonly truncationReasons: readonly string[];
  };
  readonly cfg: StaticControlFlowGraph | null;
  readonly callers: readonly Extract<FunctionProof, { readonly kind: "direct-call" }>[];
  readonly outgoingCalls: readonly StaticCallEdge[];
  readonly returnSites: readonly number[];
  readonly unresolvedExits: readonly StaticUnresolvedEdge[];
}

function functionError(
  category: NdsFunctionErrorCategory,
  message: string,
): NdsError<AnyNdsErrorCategory> {
  return new NdsError(category as AnyNdsErrorCategory, message);
}

function validatePositiveSafeInteger(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw functionError(
      "function-discovery-limit-exceeded",
      `${label} must be a positive safe integer`,
    );
  }
}

function validateLimits(limits: AnalyzeFunctionLimits): void {
  validatePositiveSafeInteger(limits.proof.maxComponents, "Maximum proof component count");
  validatePositiveSafeInteger(limits.proof.maxBlocks, "Maximum proof block count");
  validatePositiveSafeInteger(
    limits.proof.maxInstructions,
    "Maximum proof instruction count",
  );
  validatePositiveSafeInteger(limits.proof.maxBytes, "Maximum proof decoded byte count");
  validatePositiveSafeInteger(limits.proof.maxEdges, "Maximum proof traversal edge count");
  validatePositiveSafeInteger(limits.proof.maxXrefs, "Maximum proof call-site count");
  validatePositiveSafeInteger(limits.cfg.maxBlocks, "Maximum function CFG block count");
  validatePositiveSafeInteger(
    limits.cfg.maxInstructions,
    "Maximum function CFG instruction count",
  );
  validatePositiveSafeInteger(limits.cfg.maxBytes, "Maximum function CFG decoded byte count");
  validatePositiveSafeInteger(limits.cfg.maxEdges, "Maximum function CFG traversal edge count");
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

function resolveRequestedSource(
  map: NdsRomMap,
  request: AnalyzeNdsFunctionRequest,
): NdsCodeSource {
  let resolution;
  try {
    resolution = resolveNdsCodeSource(map, {
      processor: request.processor,
      runtimeAddress: request.runtimeAddress,
      mode: request.mode,
      ...(request.overlayId === undefined
        ? {}
        : { overlayId: request.overlayId }),
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw functionError(
      "function-entry-not-uniquely-resolved",
      `Requested function entry could not be resolved: ${message}`,
    );
  }

  if (resolution.status !== "resolved") {
    throw functionError(
      "function-entry-not-uniquely-resolved",
      `Requested function entry did not resolve uniquely: ${resolution.status}`,
    );
  }
  return resolution.source;
}

function isProgramEntry(
  map: NdsRomMap,
  identity: ProvenFunctionIdentity,
): boolean {
  if (identity.component !== "main" || identity.mode !== "arm") {
    return false;
  }
  const executable = identity.processor === "arm9"
    ? map.header.arm9
    : map.header.arm7;
  return identity.runtimeAddress === executable.entryAddress;
}

function programEntryProof(
  map: NdsRomMap,
  identity: ProvenFunctionIdentity,
): Extract<FunctionProof, { readonly kind: "program-entry" }> | null {
  if (!isProgramEntry(map, identity)) {
    return null;
  }
  const executable = identity.processor === "arm9"
    ? map.header.arm9
    : map.header.arm7;
  return {
    kind: "program-entry",
    processor: identity.processor,
    headerEntryAddress: executable.entryAddress,
  };
}

function sourceForReference(
  map: NdsRomMap,
  reference: StaticReference,
): NdsCodeSource | null {
  let resolution;
  try {
    resolution = resolveNdsCodeSource(map, {
      processor: reference.source.processor,
      runtimeAddress: reference.source.instructionAddress,
      mode: reference.source.mode,
      ...(reference.source.overlayId === null
        ? {}
        : { overlayId: reference.source.overlayId }),
    });
  } catch {
    return null;
  }
  return resolution.status === "resolved" ? resolution.source : null;
}

function proofFromReference(
  map: NdsRomMap,
  reference: StaticReference,
  requested: ProvenFunctionIdentity,
): Extract<FunctionProof, { readonly kind: "direct-call" }> | null {
  if (reference.kind !== "direct-call" || reference.target.mode === null) {
    return null;
  }
  if (reference.target.mode !== requested.mode) {
    return null;
  }

  const callerSource = sourceForReference(map, reference);
  if (callerSource === null) {
    return null;
  }

  let targetResolution;
  try {
    targetResolution = resolveNdsControlFlowTarget(
      map,
      callerSource,
      reference.target.runtimeAddress,
      reference.target.mode,
    );
  } catch {
    return null;
  }
  if (targetResolution.status !== "resolved") {
    return null;
  }

  const target = identityFromSource(targetResolution.source);
  if (provenFunctionId(target) !== provenFunctionId(requested)) {
    return null;
  }

  return {
    kind: "direct-call",
    caller: {
      functionId: null,
      component: reference.source.component,
      overlayId: reference.source.overlayId,
      instructionAddress: reference.source.instructionAddress,
      instructionRomOffset: reference.source.instructionRomOffset,
      mode: reference.source.mode,
    },
    target,
  };
}

function proofKey(proof: FunctionProof): string {
  if (proof.kind === "program-entry") {
    return `program:${proof.processor}:${proof.headerEntryAddress.toString(16)}`;
  }
  return [
    "call",
    proof.caller.component,
    proof.caller.overlayId ?? "main",
    proof.caller.instructionAddress.toString(16),
    proof.caller.mode,
    provenFunctionId(proof.target),
  ].join(":");
}

function deduplicateProofs(proofs: readonly FunctionProof[]): FunctionProof[] {
  const byKey = new Map<string, FunctionProof>();
  for (const proof of proofs) {
    byKey.set(proofKey(proof), proof);
  }
  return [...byKey.values()].sort(compareFunctionProof);
}

function graphForResult(
  result: Awaited<ReturnType<typeof analyzeNdsControlFlowWithReader>>,
): StaticControlFlowGraph {
  if (!("blocks" in result)) {
    throw functionError(
      "function-entry-not-uniquely-resolved",
      `Requested function CFG could not be resolved: ${result.status}`,
    );
  }
  return result;
}

export async function analyzeNdsFunction(
  map: NdsRomMap,
  request: AnalyzeNdsFunctionRequest,
  limits: AnalyzeFunctionLimits,
  backend: ArmDisassemblyBackend,
): Promise<AnalyzeNdsFunctionResult> {
  validateLimits(limits);

  const requestedSource = resolveRequestedSource(map, request);
  const entry = identityFromSource(requestedSource);

  // Validate function-specific scope/seed semantics before invoking the
  // lower-level reference scanner, whose public errors use reference terms.
  prepareFunctionSearch(
    map,
    request.processor,
    request.proofScope,
    request.seeds,
  );

  return await withValidatedNdsCodeReader(map, async (read) => {
    const xrefs = await findNdsXrefsWithReader(
      map,
      {
        processor: request.processor,
        target: { targetRuntimeAddress: request.runtimeAddress },
        scope: request.proofScope as ReferenceSearchScope,
        seeds: request.seeds as readonly ReferenceSearchSeed[],
      },
      limits.proof,
      backend,
      read,
    );

    const proofs: FunctionProof[] = [];
    const programProof = programEntryProof(map, entry);
    if (programProof !== null) {
      proofs.push(programProof);
    }
    for (const reference of xrefs.xrefs) {
      const proof = proofFromReference(map, reference, entry);
      if (proof !== null) {
        proofs.push(proof);
      }
    }
    const evidence = deduplicateProofs(proofs);
    const callers = evidence.filter(
      (proof): proof is Extract<FunctionProof, { readonly kind: "direct-call" }> =>
        proof.kind === "direct-call",
    );

    const proofStatus: AnalyzeFunctionProofStatus = evidence.length > 0
      ? "proven"
      : xrefs.status === "complete"
        ? "not-proven-function-entry"
        : "proof-inconclusive";

    const proofSearch = {
      status: xrefs.status,
      coverage: xrefs.coverage,
      truncationReasons: xrefs.truncationReasons,
    } as const;

    if (proofStatus !== "proven") {
      return {
        proofStatus,
        entry,
        evidence,
        proofSearch,
        cfg: null,
        callers,
        outgoingCalls: [],
        returnSites: [],
        unresolvedExits: [],
      };
    }

    const cfg = graphForResult(await analyzeNdsControlFlowWithReader(
      map,
      {
        processor: requestedSource.processor,
        runtimeAddress: requestedSource.runtimeAddress,
        mode: requestedSource.mode,
        ...(requestedSource.overlayId === null
          ? {}
          : { overlayId: requestedSource.overlayId }),
      },
      limits.cfg,
      backend,
      read,
    ));
    const returnSites = cfg.unresolvedEdges
      .filter((edge) => edge.kind === "return")
      .map((edge) => edge.instructionAddress)
      .sort((left, right) => left - right);

    return {
      proofStatus,
      entry,
      evidence,
      proofSearch,
      cfg,
      callers,
      outgoingCalls: cfg.calls,
      returnSites,
      unresolvedExits: cfg.unresolvedEdges,
    };
  });
}
