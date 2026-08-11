import type { ArmDisassemblyBackend, ArmMode } from "../disassembly/backend.js";
import type { ControlFlowLimits } from "../nds/control-flow.js";
import type { StaticInstruction } from "../nds/disassembly.js";
import { analyzeNdsFunction } from "../nds/function-analysis.js";
import type { FunctionSearchScope, FunctionSearchSeed } from "../nds/function-source.js";
import type { NdsProcessor } from "../nds/overlays.js";
import type { NdsRomMap } from "../nds/rom-map.js";
import type { ReferenceScanLimits } from "../nds/xrefs.js";
import { disassembleReContextWindow } from "./context-window.js";
import type { ReAmbiguity, ReEvidenceEnvelope } from "./types.js";

export interface TraceNdsFunctionRequest {
  readonly processor: NdsProcessor;
  readonly runtimeAddress: number;
  readonly mode: ArmMode;
  readonly overlayId?: number | undefined;
  readonly proofScope: FunctionSearchScope;
  readonly seeds: readonly FunctionSearchSeed[];
}

export interface TraceNdsFunctionLimits {
  readonly maxCandidates: number;
  readonly maxWindowInstructions: number;
  readonly maxWindowBytes: number;
  readonly proof: ReferenceScanLimits;
  readonly cfg: ControlFlowLimits;
}

export interface TraceFunctionCandidate {
  readonly kind: "direct-caller";
  readonly callerFunctionId: string | null;
  readonly component: "main" | "overlay";
  readonly overlayId: number | null;
  readonly instructionAddress: number;
  readonly instructionRomOffset: number | null;
  readonly mode: ArmMode;
  readonly callSiteWindow: readonly StaticInstruction[];
}

interface TraceEvidence {
  readonly kind: "function-proof" | "cfg-summary";
  readonly value: unknown;
}

function requirePositiveSafeInteger(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new Error(`${label} must be a positive safe integer`);
  }
}

function validateLimits(limits: TraceNdsFunctionLimits): void {
  requirePositiveSafeInteger(limits.maxCandidates, "Maximum candidate count");
  requirePositiveSafeInteger(limits.maxWindowInstructions, "Maximum call-site instructions");
  requirePositiveSafeInteger(limits.maxWindowBytes, "Maximum call-site bytes");
}

export async function traceNdsFunction(
  map: NdsRomMap,
  request: TraceNdsFunctionRequest,
  limits: TraceNdsFunctionLimits,
  backend: ArmDisassemblyBackend,
): Promise<ReEvidenceEnvelope<TraceEvidence, TraceFunctionCandidate>> {
  validateLimits(limits);
  const analysis = await analyzeNdsFunction(
    map,
    request,
    { proof: limits.proof, cfg: limits.cfg },
    backend,
  );

  const retainedCallers = analysis.callers.slice(0, limits.maxCandidates);
  const candidates: TraceFunctionCandidate[] = [];
  const ambiguities: ReAmbiguity[] = [];

  for (const proof of retainedCallers) {
    const caller = proof.caller;
    const window = await disassembleReContextWindow(
      map,
      {
        processor: request.processor,
        runtimeAddress: caller.instructionAddress,
        mode: caller.mode,
        ...(caller.overlayId === null ? {} : { overlayId: caller.overlayId }),
      },
      {
        maxInstructions: limits.maxWindowInstructions,
        maxBytes: limits.maxWindowBytes,
      },
      backend,
    );

    if (window.instructions.length === 0) {
      ambiguities.push({
        kind: "call-site-window-unresolved",
        detail: `No bounded call-site window could be decoded around 0x${caller.instructionAddress.toString(16)}.`,
      });
    }
    if (window.backwardDecodeAmbiguous) {
      ambiguities.push({
        kind: "call-site-window-backward-decode",
        detail: `Multiple bounded Thumb predecessor decodings can reach call site 0x${caller.instructionAddress.toString(16)}; preserve that ambiguity when interpreting pre-call context.`,
      });
    }

    candidates.push({
      kind: "direct-caller",
      callerFunctionId: caller.functionId,
      component: caller.component,
      overlayId: caller.overlayId,
      instructionAddress: caller.instructionAddress,
      instructionRomOffset: caller.instructionRomOffset,
      mode: caller.mode,
      callSiteWindow: window.instructions,
    });
  }

  if (analysis.proofSearch.status !== "complete") {
    ambiguities.push({
      kind: "proof-coverage",
      detail: `Function proof search completed with ${analysis.proofSearch.status}`,
      candidates: analysis.proofSearch.coverage,
    });
  }
  if (analysis.callers.length > limits.maxCandidates) {
    ambiguities.push({
      kind: "candidate-limit",
      detail: `${analysis.callers.length - limits.maxCandidates} direct callers were omitted by maxCandidates`,
    });
  }

  const cfgSummary = analysis.cfg === null
    ? null
    : {
        status: analysis.cfg.status,
        blocks: analysis.cfg.blocks.length,
        calls: analysis.outgoingCalls.length,
        returns: analysis.returnSites.length,
        unresolvedExits: analysis.unresolvedExits.length,
        truncationReasons: analysis.cfg.truncationReasons,
      };

  const evidence: TraceEvidence[] = [
    {
      kind: "function-proof",
      value: {
        proofStatus: analysis.proofStatus,
        entry: analysis.entry,
        evidence: analysis.evidence,
        proofSearch: analysis.proofSearch,
      },
    },
  ];
  if (cfgSummary !== null) {
    evidence.push({ kind: "cfg-summary", value: cfgSummary });
  }

  return {
    operation: "re_trace_function",
    sourceRomSha256: map.sha256,
    component: {
      processor: analysis.entry.processor,
      component: analysis.entry.component,
      overlayId: analysis.entry.overlayId,
    },
    subject: {
      runtimeAddress: analysis.entry.runtimeAddress,
      mode: analysis.entry.mode,
      romOffset: analysis.entry.romOffset,
    },
    confirmedDeterministicEvidence: evidence,
    candidates,
    ambiguities,
    completedPrimitiveStages: [
      "canonical-rom-map",
      "function-entry-proof",
      ...(analysis.cfg === null ? [] : ["bounded-cfg"]),
      "direct-caller-xrefs",
      "bounded-call-site-windows",
    ],
    artifacts: [],
    recommendedNextAction: analysis.proofStatus !== "proven"
      ? "Expand deterministic proof coverage or provide exact overlay context; do not infer function semantics from an unproven entry."
      : ambiguities.some((entry) => entry.kind === "proof-coverage")
        ? "Resolve the reported proof-coverage gap before treating the caller set as complete."
        : candidates.length === 0
          ? "No deterministic direct caller was found within the requested scope; expand the bounded scope or obtain runtime evidence."
          : "Inspect the bounded caller candidates; escalate only a specific candidate when additional evidence is required.",
  };
}
