import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

import type { ServerConfig } from "../config.js";
import { resolveInside } from "../security/paths.js";
import { DisassemblyBackendError } from "../services/disassembly/backend.js";
import { createCapstoneArmBackend } from "../services/disassembly/capstone.js";
import { NdsError } from "../services/nds/errors.js";
import type { FunctionSearchScope } from "../services/nds/function-source.js";
import { readNdsRomMap, type NdsRomMap } from "../services/nds/rom-map.js";
import type { ReferenceSearchScope } from "../services/nds/xref-source.js";
import { investigateNdsDataUsage } from "../services/re-orchestration/data-usage.js";
import { decompileReCandidate } from "../services/re-orchestration/decompile-candidate.js";
import {
  InvestigationJournalError,
  persistInvestigationResult,
} from "../services/re-orchestration/investigation-journal.js";
import { persistInvestigationResumeArtifact } from "../services/re-orchestration/resume-artifact.js";
import { resumeInvestigation } from "../services/re-orchestration/resume.js";
import { traceNdsFunction } from "../services/re-orchestration/trace-function.js";
import type { ReEvidenceEnvelope } from "../services/re-orchestration/types.js";

const uint32Schema = z.number().int().min(0).max(0xffffffff);
const processorSchema = z.enum(["arm9", "arm7"]);
const modeSchema = z.enum(["arm", "thumb"]);
const overlayIdsSchema = z.array(uint32Schema).max(32).default([]);
const seedsSchema = z.array(z.object({
  runtimeAddress: uint32Schema,
  mode: modeSchema,
  overlayId: uint32Schema.optional(),
})).max(32).default([]);

const candidateLimitSchema = z.number().int().min(1).max(64).default(16);
const componentLimitSchema = z.number().int().min(1).max(64).default(16);
const proofInstructionLimitSchema = z.number().int().min(1).max(8192).default(2048);
const proofByteLimitSchema = z.number().int().min(4).max(65536).default(8192);
const cfgInstructionLimitSchema = z.number().int().min(1).max(2048).default(512);
const cfgByteLimitSchema = z.number().int().min(4).max(16384).default(2048);
const windowInstructionLimitSchema = z.number().int().min(1).max(16).default(4);
const windowByteLimitSchema = z.number().int().min(2).max(128).default(32);
const decompileCharacterLimitSchema = z.number().int().min(256).max(32768).default(8192);

function scopeFromInput(
  includeMain: boolean,
  overlayIds: readonly number[],
  requiredOverlayId?: number,
): FunctionSearchScope & ReferenceSearchScope {
  const normalizedOverlayIds = [...new Set([
    ...overlayIds,
    ...(requiredOverlayId === undefined ? [] : [requiredOverlayId]),
  ])].sort((left, right) => left - right);

  if (normalizedOverlayIds.length === 0) {
    if (!includeMain) {
      throw new Error("Static RE scope must include main code or at least one explicit overlay ID");
    }
    return { kind: "main" };
  }
  return includeMain
    ? { kind: "main-and-overlays", overlayIds: normalizedOverlayIds }
    : { kind: "overlay", overlayIds: normalizedOverlayIds };
}

function textResultFromText(text: string, isError = false) {
  return {
    content: [{ type: "text" as const, text }],
    isError,
  };
}

function boundedResult(
  config: ServerConfig,
  operation: string,
  value: unknown,
  isError = false,
) {
  const text = JSON.stringify(value, null, 2);
  if (!isError && Buffer.byteLength(text, "utf8") > config.maxOutputBytes) {
    return textResultFromText(JSON.stringify({
      error: "Serialized RE orchestration result exceeds RE_MCP_MAX_OUTPUT_BYTES",
      operation,
      category: "output-bound-exceeded",
      correctiveAction: "Reduce candidate, scan, CFG, decompiler, or call-site window maxima and retry.",
    }, null, 2), true);
  }
  return textResultFromText(text, isError);
}

function errorResult(config: ServerConfig, operation: string, error: unknown) {
  const category = error instanceof DisassemblyBackendError
    ? error.category
    : error instanceof NdsError
      ? String(error.category)
      : error instanceof InvestigationJournalError
        ? error.category
        : "orchestration-failure";
  return boundedResult(config, operation, {
    error: error instanceof Error ? error.message : String(error),
    operation,
    category,
    correctiveAction: error instanceof InvestigationJournalError
      ? "Repair or remove only the corrupted exact-ROM-SHA investigation state after preserving it for diagnosis; RE-MCP will not report high-level success without durable resumable state."
      : "Narrow the deterministic analysis scope, verify the exact ROM/component inputs, and retry without guessing through unresolved evidence.",
  }, true);
}

function derivedGraphLimit(instructions: number, ceiling: number): number {
  return Math.max(1, Math.min(ceiling, instructions));
}

async function persistEnvelope<T extends ReEvidenceEnvelope>(
  map: NdsRomMap,
  config: ServerConfig,
  normalizedInputs: unknown,
  result: T,
): Promise<T & { readonly checkpointRevision: number }> {
  const source = { sha256: map.sha256, sha256Prefix: map.sha256Prefix };
  const resumeArtifact = await persistInvestigationResumeArtifact(
    source,
    config.workspaceRoot,
    result,
  );
  const persistedArtifacts = [...result.artifacts, resumeArtifact];
  const resultWithArtifact = { ...result, artifacts: persistedArtifacts };
  const persisted = await persistInvestigationResult(
    source,
    config.workspaceRoot,
    {
      operation: result.operation,
      normalizedInputs,
      completedStages: result.completedPrimitiveStages,
      artifacts: persistedArtifacts,
      result: resultWithArtifact,
      recommendedNextAction: result.recommendedNextAction,
    },
  );
  return {
    ...resultWithArtifact,
    checkpointRevision: persisted.entry.sequence,
  } as T & { readonly checkpointRevision: number };
}

export function registerReOrchestrationTools(
  server: McpServer,
  config: ServerConfig,
): void {
  server.tool(
    "re_trace_function",
    "Prove one NDS function, collect bounded direct callers/CFG context, and persist exact-ROM-SHA resumable evidence without semantic guessing.",
    {
      rom: z.string().min(1),
      processor: processorSchema,
      runtimeAddress: uint32Schema,
      mode: modeSchema,
      overlayId: uint32Schema.optional(),
      includeMain: z.boolean().default(true),
      overlayIds: overlayIdsSchema,
      seeds: seedsSchema,
      maxCandidates: candidateLimitSchema,
      maxProofComponents: componentLimitSchema,
      maxProofInstructions: proofInstructionLimitSchema,
      maxProofBytes: proofByteLimitSchema,
      maxCfgInstructions: cfgInstructionLimitSchema,
      maxCfgBytes: cfgByteLimitSchema,
      maxWindowInstructions: windowInstructionLimitSchema,
      maxWindowBytes: windowByteLimitSchema,
    },
    async (input) => {
      const operation = "re_trace_function";
      try {
        const romPath = resolveInside(config.workspaceRoot, input.rom);
        const map = await readNdsRomMap(romPath);
        const backend = await createCapstoneArmBackend();
        try {
          const result = await traceNdsFunction(
            map,
            {
              processor: input.processor,
              runtimeAddress: input.runtimeAddress,
              mode: input.mode,
              ...(input.overlayId === undefined ? {} : { overlayId: input.overlayId }),
              proofScope: scopeFromInput(input.includeMain, input.overlayIds, input.overlayId),
              seeds: input.seeds,
            },
            {
              maxCandidates: input.maxCandidates,
              maxWindowInstructions: input.maxWindowInstructions,
              maxWindowBytes: input.maxWindowBytes,
              proof: {
                maxComponents: input.maxProofComponents,
                maxBlocks: derivedGraphLimit(input.maxProofInstructions, 512),
                maxInstructions: input.maxProofInstructions,
                maxBytes: input.maxProofBytes,
                maxEdges: derivedGraphLimit(input.maxProofInstructions * 2, 4096),
                maxXrefs: Math.max(input.maxCandidates, Math.min(2048, input.maxCandidates * 4)),
              },
              cfg: {
                maxBlocks: derivedGraphLimit(input.maxCfgInstructions, 256),
                maxInstructions: input.maxCfgInstructions,
                maxBytes: input.maxCfgBytes,
                maxEdges: derivedGraphLimit(input.maxCfgInstructions * 2, 1024),
              },
            },
            backend,
          );
          const persisted = await persistEnvelope(map, config, input, result);
          return boundedResult(config, operation, persisted);
        } finally {
          backend.close();
        }
      } catch (error) {
        return errorResult(config, operation, error);
      }
    },
  );

  server.tool(
    "re_investigate_data_usage",
    "Resolve one NDS data address, collect bounded direct users/context, and persist exact-ROM-SHA resumable evidence without semantic ranking.",
    {
      rom: z.string().min(1),
      processor: processorSchema,
      runtimeAddress: uint32Schema,
      includeMain: z.boolean().default(true),
      overlayIds: overlayIdsSchema,
      seeds: seedsSchema,
      maxCandidates: candidateLimitSchema,
      maxScanComponents: componentLimitSchema,
      maxScanInstructions: proofInstructionLimitSchema,
      maxScanBytes: proofByteLimitSchema,
      maxWindowInstructions: windowInstructionLimitSchema,
      maxWindowBytes: windowByteLimitSchema,
    },
    async (input) => {
      const operation = "re_investigate_data_usage";
      try {
        const romPath = resolveInside(config.workspaceRoot, input.rom);
        const map = await readNdsRomMap(romPath);
        const backend = await createCapstoneArmBackend();
        try {
          const result = await investigateNdsDataUsage(
            map,
            {
              processor: input.processor,
              runtimeAddress: input.runtimeAddress,
              scope: scopeFromInput(input.includeMain, input.overlayIds),
              seeds: input.seeds,
            },
            {
              maxCandidates: input.maxCandidates,
              maxWindowInstructions: input.maxWindowInstructions,
              maxWindowBytes: input.maxWindowBytes,
              scan: {
                maxComponents: input.maxScanComponents,
                maxBlocks: derivedGraphLimit(input.maxScanInstructions, 512),
                maxInstructions: input.maxScanInstructions,
                maxBytes: input.maxScanBytes,
                maxEdges: derivedGraphLimit(input.maxScanInstructions * 2, 4096),
                maxXrefs: input.maxCandidates,
              },
            },
            backend,
          );
          const persisted = await persistEnvelope(map, config, input, result);
          return boundedResult(config, operation, persisted);
        } finally {
          backend.close();
        }
      } catch (error) {
        return errorResult(config, operation, error);
      }
    },
  );

  server.tool(
    "re_decompile_candidate",
    "Escalate exactly one already-identified canonical candidate to an existing current exact-ROM-SHA Ghidra project. Never bootstraps/reconciles automatically; persists the bounded non-authoritative decompiler candidate before success.",
    {
      rom: z.string().min(1),
      processor: processorSchema,
      runtimeAddress: uint32Schema,
      overlayId: uint32Schema.optional(),
      maxCharacters: decompileCharacterLimitSchema,
    },
    async (input) => {
      const operation = "re_decompile_candidate";
      try {
        const romPath = resolveInside(config.workspaceRoot, input.rom);
        const map = await readNdsRomMap(romPath);
        const result = await decompileReCandidate(
          romPath,
          {
            processor: input.processor,
            runtimeAddress: input.runtimeAddress,
            ...(input.overlayId === undefined ? {} : { overlayId: input.overlayId }),
            maxCharacters: input.maxCharacters,
          },
          config,
        );
        const persisted = await persistEnvelope(map, config, input, result);
        return boundedResult(config, operation, persisted);
      } catch (error) {
        return errorResult(config, operation, error);
      }
    },
  );

  server.tool(
    "re_resume_investigation",
    "Revalidate the ROM SHA and return integrity-bound resumable evidence, checkpoint state, and unresolved next actions.",
    { rom: z.string().min(1) },
    async ({ rom }) => {
      const operation = "re_resume_investigation";
      try {
        const result = await resumeInvestigation(
          resolveInside(config.workspaceRoot, rom),
          config,
        );
        return boundedResult(config, operation, result);
      } catch (error) {
        return errorResult(config, operation, error);
      }
    },
  );
}
