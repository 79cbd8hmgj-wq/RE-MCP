import type { ArmMode } from "../disassembly/backend.js";
import type { NdsProcessor } from "../nds/overlays.js";

export interface ReComponentIdentity {
  readonly processor: NdsProcessor;
  readonly component: "main" | "overlay" | "unresolved";
  readonly overlayId: number | null;
}

export interface ReSubject {
  readonly runtimeAddress: number;
  readonly mode: ArmMode | null;
  readonly romOffset: number | null;
}

export interface ReAmbiguity {
  readonly kind: string;
  readonly detail: string;
  readonly candidates?: readonly unknown[];
}

export interface ReArtifactReference {
  readonly kind: string;
  readonly path?: string;
  readonly sha256?: string;
}

export interface ReEvidenceEnvelope<
  Evidence = unknown,
  Candidate = unknown,
> {
  readonly operation: string;
  readonly sourceRomSha256: string;
  readonly component: ReComponentIdentity;
  readonly subject: ReSubject;
  readonly confirmedDeterministicEvidence: readonly Evidence[];
  readonly candidates: readonly Candidate[];
  readonly ambiguities: readonly ReAmbiguity[];
  readonly completedPrimitiveStages: readonly string[];
  readonly artifacts: readonly ReArtifactReference[];
  readonly recommendedNextAction: string | null;
  readonly checkpointRevision?: number;
}
