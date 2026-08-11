import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

import type { ServerConfig } from "../config.js";
import { resolveInside } from "../security/paths.js";
import { DisassemblyBackendError } from "../services/disassembly/backend.js";
import { createCapstoneArmBackend } from "../services/disassembly/capstone.js";
import { NdsError } from "../services/nds/errors.js";
import type { FunctionSearchScope } from "../services/nds/function-source.js";
import { readNdsRomMap } from "../services/nds/rom-map.js";
import type { ReferenceSearchScope } from "../services/nds/xref-source.js";
import { investigateNdsDataUsage } from "../services/re-orchestration/data-usage.js";
import { traceNdsFunction } from "../services/re-orchestration/trace-function.js";

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
      correctiveAction: "Reduce candidate, scan, CFG, or call-site window maxima and retry.",
    }, null, 2), true);
  }
  return textResultFromText(text, isError);
}

function errorResult(config: ServerConfig, operation: string, error: unknown) {
  const category = error instanceof DisassemblyBackendError
    ? error.category
    : error instanceof NdsError
      ? String(error.category)
      : "orchestration-failure";
  return boundedResult(config, operation, {
    error: error instanceof Error ? error.message : String(error),
    operation,
    category,
    correctiveAction:
      "Narrow the deterministic static-analysis scope, verify the exact ROM/component inputs, and retry without guessing through unresolved evidence.",
  }, true);
}

function derivedGraphLimit(instructions: number, ceiling: number): number {
  return Math.max(1, Math.min(ceiling, instructions));
}

export function registerReOrchestrationTools(
  server: McpServer,
  config: ServerConfig,
): void {
  server.tool(
    "re_trace_function",
    "Read-only bounded orchestration for one canonical NDS function: prove the entry, collect direct callers, summarize CFG evidence, and return compact call-site windows without semantic guessing.",
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
    async ({
      rom,
      processor,
      runtimeAddress,
      mode,
      overlayId,
      includeMain,
      overlayIds,
      seeds,
      maxCandidates,
      maxProofComponents,
      maxProofInstructions,
      maxProofBytes,
      maxCfgInstructions,
      maxCfgBytes,
      maxWindowInstructions,
      maxWindowBytes,
    }) => {
      const operation = "re_trace_function";
      try {
        const map = await readNdsRomMap(resolveInside(config.workspaceRoot, rom));
        const backend = await createCapstoneArmBackend();
        try {
          const result = await traceNdsFunction(
            map,
            {
              processor,
              runtimeAddress,
              mode,
              ...(overlayId === undefined ? {} : { overlayId }),
              proofScope: scopeFromInput(includeMain, overlayIds, overlayId),
              seeds,
            },
            {
              maxCandidates,
              maxWindowInstructions,
              maxWindowBytes,
              proof: {
                maxComponents: maxProofComponents,
                maxBlocks: derivedGraphLimit(maxProofInstructions, 512),
                maxInstructions: maxProofInstructions,
                maxBytes: maxProofBytes,
                maxEdges: derivedGraphLimit(maxProofInstructions * 2, 4096),
                maxXrefs: Math.max(maxCandidates, Math.min(2048, maxCandidates * 4)),
              },
              cfg: {
                maxBlocks: derivedGraphLimit(maxCfgInstructions, 256),
                maxInstructions: maxCfgInstructions,
                maxBytes: maxCfgBytes,
                maxEdges: derivedGraphLimit(maxCfgInstructions * 2, 1024),
              },
            },
            backend,
          );
          return boundedResult(config, operation, result);
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
    "Read-only bounded orchestration for a known NDS runtime/data address or deterministic hit: resolve canonical ownership, find direct users, and return compact source windows without semantic ranking.",
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
    async ({
      rom,
      processor,
      runtimeAddress,
      includeMain,
      overlayIds,
      seeds,
      maxCandidates,
      maxScanComponents,
      maxScanInstructions,
      maxScanBytes,
      maxWindowInstructions,
      maxWindowBytes,
    }) => {
      const operation = "re_investigate_data_usage";
      try {
        const map = await readNdsRomMap(resolveInside(config.workspaceRoot, rom));
        const backend = await createCapstoneArmBackend();
        try {
          const result = await investigateNdsDataUsage(
            map,
            {
              processor,
              runtimeAddress,
              scope: scopeFromInput(includeMain, overlayIds),
              seeds,
            },
            {
              maxCandidates,
              maxWindowInstructions,
              maxWindowBytes,
              scan: {
                maxComponents: maxScanComponents,
                maxBlocks: derivedGraphLimit(maxScanInstructions, 512),
                maxInstructions: maxScanInstructions,
                maxBytes: maxScanBytes,
                maxEdges: derivedGraphLimit(maxScanInstructions * 2, 4096),
                maxXrefs: maxCandidates,
              },
            },
            backend,
          );
          return boundedResult(config, operation, result);
        } finally {
          backend.close();
        }
      } catch (error) {
        return errorResult(config, operation, error);
      }
    },
  );
}
