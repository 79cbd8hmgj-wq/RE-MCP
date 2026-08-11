import type { ServerConfig } from "../../config.js";
import {
  readControllerCheckpoint,
  type ControllerCheckpoint,
} from "../controller-checkpoint.js";
import { readNdsRomMap } from "../nds/rom-map.js";
import {
  readInvestigationJournal,
  type InvestigationArtifactHash,
} from "./investigation-journal.js";

export interface ResumeInvestigationResult {
  readonly operation: "re_resume_investigation";
  readonly sourceRomSha256: string;
  readonly sourceRomSha256Prefix: string;
  readonly journal: {
    readonly exists: boolean;
    readonly entryCount: number;
    readonly lastSequence: number;
    readonly journalSha256: string | null;
    readonly projectionSha256: string | null;
    readonly completedOperations: readonly {
      readonly sequence: number;
      readonly operationId: string;
      readonly operation: string;
      readonly resultDigest: string;
    }[];
    readonly completedStages: readonly string[];
    readonly artifactHashes: readonly InvestigationArtifactHash[];
  };
  readonly controllerState: {
    readonly authority: "controller-state-only";
    readonly exists: boolean;
    readonly revision: number;
    readonly contentSha256: string | null;
    readonly checkpoint: ControllerCheckpoint | null;
  };
  readonly smallestUnresolvedNextActions: readonly string[];
  readonly replayRequired: false;
}

function mechanicalNextActions(
  journalExists: boolean,
  projected: readonly string[],
): readonly string[] {
  if (projected.length > 0) return projected.slice(0, 4);
  if (!journalExists) {
    return [
      "Run one bounded deterministic high-level static operation for the current objective; no prior high-level analysis is journaled for this exact ROM SHA.",
    ];
  }
  return [
    "Use the latest integrity-bound deterministic result digest/artifact metadata to choose the next bounded high-level operation; do not replay completed primitive stages unless evidence is stale or incomplete.",
  ];
}

export async function resumeInvestigation(
  romPath: string,
  config: ServerConfig,
): Promise<ResumeInvestigationResult> {
  const map = await readNdsRomMap(romPath);
  const source = { sha256: map.sha256, sha256Prefix: map.sha256Prefix };
  const [journal, checkpointRead] = await Promise.all([
    readInvestigationJournal(source, config.workspaceRoot),
    readControllerCheckpoint(source, config.workspaceRoot),
  ]);
  const projection = journal.projection;
  const checkpoint = checkpointRead.exists ? checkpointRead.checkpoint : null;

  return {
    operation: "re_resume_investigation",
    sourceRomSha256: map.sha256,
    sourceRomSha256Prefix: map.sha256Prefix,
    journal: {
      exists: journal.entries.length > 0,
      entryCount: journal.entries.length,
      lastSequence: journal.metadata?.lastSequence ?? 0,
      journalSha256: journal.metadata?.journalSha256 ?? null,
      projectionSha256: journal.metadata?.projectionSha256 ?? null,
      completedOperations: projection?.completedOperations ?? [],
      completedStages: projection?.completedStages ?? [],
      artifactHashes: projection?.artifactHashes ?? [],
    },
    controllerState: {
      authority: "controller-state-only",
      exists: checkpoint !== null,
      revision: checkpoint?.revision ?? 0,
      contentSha256: checkpoint?.contentSha256 ?? null,
      checkpoint,
    },
    smallestUnresolvedNextActions: mechanicalNextActions(
      journal.entries.length > 0,
      projection?.recommendedNextActions ?? [],
    ),
    replayRequired: false,
  };
}
