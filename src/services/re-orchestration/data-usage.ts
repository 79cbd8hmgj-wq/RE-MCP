import type { ArmDisassemblyBackend } from "../disassembly/backend.js";
import type { StaticInstruction } from "../nds/disassembly.js";
import type { NdsProcessor } from "../nds/overlays.js";
import type { StaticReference } from "../nds/references.js";
import { resolveRuntimeAddress, type RuntimeResolution } from "../nds/resolver.js";
import type { NdsRomMap } from "../nds/rom-map.js";
import type { ReferenceSearchScope, ReferenceSearchSeed } from "../nds/xref-source.js";
import { findNdsXrefs, type ReferenceScanLimits } from "../nds/xrefs.js";
import { disassembleReContextWindow } from "./context-window.js";
import type { ReAmbiguity, ReComponentIdentity, ReEvidenceEnvelope } from "./types.js";

export interface InvestigateNdsDataUsageRequest {
  readonly processor: NdsProcessor;
  readonly runtimeAddress: number;
  readonly scope: ReferenceSearchScope;
  readonly seeds: readonly ReferenceSearchSeed[];
}

export interface InvestigateNdsDataUsageLimits {
  readonly maxCandidates: number;
  readonly maxWindowInstructions: number;
  readonly maxWindowBytes: number;
  readonly scan: ReferenceScanLimits;
}

export interface DataUsageCandidate {
  readonly kind: "direct-reference";
  readonly reference: StaticReference;
  readonly callSiteWindow: readonly StaticInstruction[];
}

interface DataUsageEvidence {
  readonly kind: "runtime-resolution" | "xref-scan";
  readonly value: unknown;
}

function requirePositiveSafeInteger(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new Error(`${label} must be a positive safe integer`);
  }
}

function validateLimits(limits: InvestigateNdsDataUsageLimits): void {
  requirePositiveSafeInteger(limits.maxCandidates, "Maximum candidate count");
  requirePositiveSafeInteger(limits.maxWindowInstructions, "Maximum reference-window instructions");
  requirePositiveSafeInteger(limits.maxWindowBytes, "Maximum reference-window bytes");
}

function componentForResolution(
  processor: NdsProcessor,
  resolution: RuntimeResolution,
): ReComponentIdentity {
  if (resolution.status === "ambiguous-runtime-address" || resolution.status === "unmapped") {
    return { processor, component: "unresolved", overlayId: null };
  }
  const candidate = resolution.candidate;
  return {
    processor,
    component: candidate.overlayId === null ? "main" : "overlay",
    overlayId: candidate.overlayId,
  };
}

function romOffsetForResolution(resolution: RuntimeResolution): number | null {
  if (resolution.status === "resolved") {
    return resolution.candidate.romOffset;
  }
  return null;
}

function ambiguityForResolution(resolution: RuntimeResolution): ReAmbiguity[] {
  switch (resolution.status) {
    case "ambiguous-runtime-address":
      return [{
        kind: "runtime-ownership",
        detail: "The runtime address belongs to multiple canonical static candidates; no loaded overlay is inferred.",
        candidates: resolution.candidates,
      }];
    case "unmapped":
      return [{
        kind: "runtime-unmapped",
        detail: "The requested runtime address is outside canonical static mappings for the selected processor.",
      }];
    case "runtime-only-bss":
      return [{
        kind: "runtime-only",
        detail: "The target is overlay BSS/runtime-only state and has no initialized ROM byte mapping.",
        candidates: [resolution.candidate],
      }];
    case "compressed-no-direct-rom-mapping":
      return [{
        kind: "derived-runtime-image",
        detail: "The target is inside a compressed overlay runtime image and has no fabricated direct ROM offset.",
        candidates: [resolution.candidate],
      }];
    case "resolved":
      return [];
  }
}

export async function investigateNdsDataUsage(
  map: NdsRomMap,
  request: InvestigateNdsDataUsageRequest,
  limits: InvestigateNdsDataUsageLimits,
  backend: ArmDisassemblyBackend,
): Promise<ReEvidenceEnvelope<DataUsageEvidence, DataUsageCandidate>> {
  validateLimits(limits);
  const resolution = resolveRuntimeAddress(map, request.runtimeAddress, request.processor);
  const xrefs = await findNdsXrefs(
    map,
    {
      processor: request.processor,
      target: { targetRuntimeAddress: request.runtimeAddress },
      scope: request.scope,
      seeds: request.seeds,
    },
    { ...limits.scan, maxXrefs: Math.min(limits.scan.maxXrefs, limits.maxCandidates) },
    backend,
  );

  const candidates: DataUsageCandidate[] = [];
  const ambiguities = ambiguityForResolution(resolution);
  for (const reference of xrefs.xrefs.slice(0, limits.maxCandidates)) {
    const source = reference.source;
    const window = await disassembleReContextWindow(
      map,
      {
        processor: request.processor,
        runtimeAddress: source.instructionAddress,
        mode: source.mode,
        ...(source.overlayId === null ? {} : { overlayId: source.overlayId }),
      },
      {
        maxInstructions: limits.maxWindowInstructions,
        maxBytes: limits.maxWindowBytes,
      },
      backend,
    );
    if (window.instructions.length === 0) {
      ambiguities.push({
        kind: "reference-window-unresolved",
        detail: `No bounded reference window could be decoded around 0x${source.instructionAddress.toString(16)}.`,
      });
    }
    if (window.backwardDecodeAmbiguous) {
      ambiguities.push({
        kind: "reference-window-backward-decode",
        detail: `Multiple bounded Thumb predecessor decodings can reach reference site 0x${source.instructionAddress.toString(16)}; preserve that ambiguity when interpreting pre-reference context.`,
      });
    }
    candidates.push({
      kind: "direct-reference",
      reference,
      callSiteWindow: window.instructions,
    });
  }

  if (xrefs.status !== "complete") {
    ambiguities.push({
      kind: "xref-coverage",
      detail: `Reference scan completed with ${xrefs.status}`,
      candidates: xrefs.coverage,
    });
  }

  const evidence: DataUsageEvidence[] = [
    { kind: "runtime-resolution", value: resolution },
    {
      kind: "xref-scan",
      value: {
        status: xrefs.status,
        target: xrefs.target,
        scan: xrefs.scan,
        coverage: xrefs.coverage,
        truncationReasons: xrefs.truncationReasons,
      },
    },
  ];

  return {
    operation: "re_investigate_data_usage",
    sourceRomSha256: map.sha256,
    component: componentForResolution(request.processor, resolution),
    subject: {
      runtimeAddress: request.runtimeAddress,
      mode: null,
      romOffset: romOffsetForResolution(resolution),
    },
    confirmedDeterministicEvidence: evidence,
    candidates,
    ambiguities,
    completedPrimitiveStages: [
      "canonical-rom-map",
      "runtime-address-resolution",
      "bounded-direct-xrefs",
      "bounded-reference-windows",
    ],
    artifacts: [],
    recommendedNextAction: resolution.status === "ambiguous-runtime-address"
      ? "Preserve every reported ownership candidate and obtain overlay/runtime evidence before choosing one."
      : xrefs.status !== "complete"
        ? "Resolve the reported xref coverage gap before treating the user set as complete."
        : candidates.length === 0
          ? "No direct deterministic users were found in the requested scope; expand the bounded scope or provide additional deterministic seeds."
          : "Inspect the bounded direct-reference candidates without assigning gameplay semantics automatically.",
  };
}
