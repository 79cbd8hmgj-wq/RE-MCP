import type { ServerConfig } from "../../config.js";
import {
  decompileNdsGhidraFunction,
  type GhidraInspectionAuthorityResult,
} from "../nds/ghidra-inspection.js";
import type { NdsProcessor } from "../nds/overlays.js";
import { resolveRuntimeAddress } from "../nds/resolver.js";
import { readNdsRomMap } from "../nds/rom-map.js";
import type { ReAmbiguity, ReEvidenceEnvelope } from "./types.js";

export interface DecompileReCandidateRequest {
  readonly processor: NdsProcessor;
  readonly runtimeAddress: number;
  readonly overlayId?: number;
  readonly maxCharacters?: number;
}

export interface DecompileReCandidateEvidence {
  readonly kind: "deterministic-provenance";
  readonly value: {
    readonly canonical: Readonly<Record<string, unknown>>;
    readonly reMcpEvidence: Readonly<Record<string, string | null>> | null;
  };
}

export interface DecompileReCandidateResult {
  readonly authority: "non-authoritative-ghidra-candidate";
  readonly ghidraDerived: Readonly<Record<string, unknown>>;
}

function resolutionIdentity(
  processor: NdsProcessor,
  runtimeAddress: number,
  overlayId: number | undefined,
  result: ReturnType<typeof resolveRuntimeAddress>,
): {
  readonly component: "main" | "overlay" | "unresolved";
  readonly resolvedOverlayId: number | null;
  readonly romOffset: number | null;
  readonly ambiguities: readonly ReAmbiguity[];
} {
  if (result.status === "unmapped") {
    return {
      component: "unresolved",
      resolvedOverlayId: null,
      romOffset: null,
      ambiguities: [{
        kind: "runtime-unmapped",
        detail: `Runtime address 0x${runtimeAddress.toString(16)} is not canonically mapped for ${processor}.`,
      }],
    };
  }
  if (result.status === "ambiguous-runtime-address") {
    const selected = overlayId === undefined
      ? undefined
      : result.candidates.find((candidate) => candidate.overlayId === overlayId);
    if (selected === undefined) {
      return {
        component: "unresolved",
        resolvedOverlayId: null,
        romOffset: null,
        ambiguities: [{
          kind: "runtime-ownership",
          detail: "The runtime address has multiple canonical owners; an exact overlayId is required before Ghidra candidate escalation.",
          candidates: result.candidates,
        }],
      };
    }
    return {
      component: "overlay",
      resolvedOverlayId: selected.overlayId,
      romOffset: selected.romOffset,
      ambiguities: [],
    };
  }
  const candidate = result.candidate;
  if (overlayId !== undefined && candidate.overlayId !== overlayId) {
    return {
      component: "unresolved",
      resolvedOverlayId: null,
      romOffset: null,
      ambiguities: [{
        kind: "overlay-mismatch",
        detail: `Requested overlay ${overlayId} does not own runtime address 0x${runtimeAddress.toString(16)}.`,
        candidates: [candidate],
      }],
    };
  }
  return {
    component: candidate.overlayId === null ? "main" : "overlay",
    resolvedOverlayId: candidate.overlayId,
    romOffset: candidate.romOffset,
    ambiguities: [],
  };
}

export async function decompileReCandidate(
  romPath: string,
  request: DecompileReCandidateRequest,
  config: ServerConfig,
  decompile: typeof decompileNdsGhidraFunction = decompileNdsGhidraFunction,
): Promise<ReEvidenceEnvelope<DecompileReCandidateEvidence, DecompileReCandidateResult>> {
  const map = await readNdsRomMap(romPath);
  const resolution = resolveRuntimeAddress(map, request.runtimeAddress, request.processor);
  const identity = resolutionIdentity(
    request.processor,
    request.runtimeAddress,
    request.overlayId,
    resolution,
  );
  if (identity.ambiguities.length > 0) {
    return {
      operation: "re_decompile_candidate",
      sourceRomSha256: map.sha256,
      component: {
        processor: request.processor,
        component: "unresolved",
        overlayId: null,
      },
      subject: {
        runtimeAddress: request.runtimeAddress,
        mode: null,
        romOffset: null,
      },
      confirmedDeterministicEvidence: [],
      candidates: [],
      ambiguities: identity.ambiguities,
      completedPrimitiveStages: ["canonical-rom-map", "runtime-address-resolution"],
      artifacts: [],
      recommendedNextAction:
        "Resolve the reported canonical address/overlay ambiguity before requesting Ghidra enrichment.",
    };
  }

  const inspection: GhidraInspectionAuthorityResult = await decompile(
    romPath,
    {
      processor: request.processor,
      runtimeAddress: request.runtimeAddress,
      ...(request.overlayId === undefined ? {} : { overlayId: request.overlayId }),
      ...(request.maxCharacters === undefined ? {} : { maxCharacters: request.maxCharacters }),
    },
    config,
  );

  return {
    operation: "re_decompile_candidate",
    sourceRomSha256: map.sha256,
    component: {
      processor: request.processor,
      component: identity.component,
      overlayId: identity.resolvedOverlayId,
    },
    subject: {
      runtimeAddress: request.runtimeAddress,
      mode: null,
      romOffset: identity.romOffset,
    },
    confirmedDeterministicEvidence: [{
      kind: "deterministic-provenance",
      value: {
        canonical: inspection.canonical,
        reMcpEvidence: inspection.reMcpEvidence,
      },
    }],
    candidates: [{
      authority: "non-authoritative-ghidra-candidate",
      ghidraDerived: inspection.ghidraDerived,
    }],
    ambiguities: [],
    completedPrimitiveStages: [
      "canonical-rom-map",
      "runtime-address-resolution",
      "existing-ghidra-project-readiness",
      "bounded-read-only-ghidra-decompilation",
    ],
    artifacts: [],
    recommendedNextAction:
      "Compare the non-authoritative Ghidra candidate against deterministic RE-MCP evidence before drawing any semantic conclusion.",
  };
}
