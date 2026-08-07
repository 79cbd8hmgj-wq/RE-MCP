import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

import type { ServerConfig } from "../config.js";
import { resolveInside } from "../security/paths.js";
import {
  DisassemblyBackendError,
} from "../services/disassembly/backend.js";
import { createCapstoneArmBackend } from "../services/disassembly/capstone.js";
import { analyzeNdsFunction } from "../services/nds/function-analysis.js";
import { discoverNdsFunctions } from "../services/nds/function-discovery.js";
import { NdsError } from "../services/nds/errors.js";
import { readNdsRomMap } from "../services/nds/rom-map.js";

const romSchema = z.string().min(1);
const uint32Schema = z.number().int().min(0).max(0xffffffff);
const processorSchema = z.enum(["arm9", "arm7"]);
const modeSchema = z.enum(["arm", "thumb"]);

const functionScopeSchema = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("main") }),
  z.object({
    kind: z.literal("overlay"),
    overlayIds: z.array(uint32Schema).min(1).max(128),
  }),
  z.object({
    kind: z.literal("main-and-overlays"),
    overlayIds: z.array(uint32Schema).min(1).max(128),
  }),
  z.object({ kind: z.literal("all-executable-components") }),
]);

const functionSeedSchema = z.object({
  runtimeAddress: uint32Schema,
  mode: modeSchema,
  overlayId: uint32Schema.optional(),
});

const functionComponentLimitSchema = z.number().int().min(1).max(128).default(32);
const functionLimitSchema = z.number().int().min(1).max(1024).default(128);
const functionCallSiteLimitSchema = z.number().int().min(1).max(8192).default(512);
const functionBlockLimitSchema = z.number().int().min(1).max(4096).default(512);
const functionInstructionLimitSchema = z.number().int().min(1).max(32768).default(4096);
const functionByteLimitSchema = z.number().int().min(2).max(262144).default(32768);
const functionEdgeLimitSchema = z.number().int().min(1).max(16384).default(2048);

const cfgBlockLimitSchema = z.number().int().min(1).max(256).default(64);
const cfgInstructionLimitSchema = z.number().int().min(1).max(4096).default(512);
const cfgByteLimitSchema = z.number().int().min(2).max(16384).default(2048);
const cfgEdgeLimitSchema = z.number().int().min(1).max(1024).default(128);

const proofComponentLimitSchema = z.number().int().min(1).max(128).default(32);
const proofBlockLimitSchema = z.number().int().min(1).max(512).default(128);
const proofInstructionLimitSchema = z.number().int().min(1).max(16384).default(2048);
const proofByteLimitSchema = z.number().int().min(2).max(65536).default(8192);
const proofEdgeLimitSchema = z.number().int().min(1).max(4096).default(512);
const proofCallSiteLimitSchema = z.number().int().min(1).max(2048).default(256);

function textResultFromText(text: string, isError = false) {
  return {
    content: [{ type: "text" as const, text }],
    isError,
  };
}

function textResult(value: unknown, isError = false) {
  return textResultFromText(JSON.stringify(value, null, 2), isError);
}

function correctiveAction(category: string): string {
  switch (category) {
    case "invalid-rom":
      return "Use a readable Nintendo DS ROM path inside RE_MCP_WORKSPACE_ROOT and re-run ROM inspection if the source changed.";
    case "malformed-header":
    case "malformed-fat":
    case "malformed-fnt":
    case "malformed-overlay-table":
      return "Inspect the ROM structure or use a known-good ROM revision; RE-MCP will not guess through malformed metadata.";
    case "range-out-of-bounds":
      return "Use aligned ARM/Thumb addresses and bounded values that lie inside validated canonical NDS executable sources.";
    case "unknown-file-id":
      return "List NitroFS files first, then use an existing canonical file selector.";
    case "unknown-overlay-id":
      return "List overlays first, then use an existing overlay ID for the selected processor.";
    case "invalid-function-scope":
      return "Choose main, existing overlay IDs, selected main plus overlays, or all executable components without duplicate overlay IDs.";
    case "invalid-function-seed":
      return "Use an aligned ARM/Thumb seed that resolves uniquely to selected uncompressed file-backed code; seeds provide coverage only and do not prove functions.";
    case "function-entry-not-uniquely-resolved":
      return "Provide processor, ARM/Thumb mode, and overlay context when needed so the requested function entry selects one exact initialized executable source.";
    case "function-discovery-limit-exceeded":
      return "Use positive bounded function-discovery, proof-search, and CFG limits within the documented maxima.";
    case "reference-scan-limit-exceeded":
      return "Use positive bounded proof-search limits within the documented function-analysis maxima.";
    case "invalid-reference-scope":
    case "invalid-reference-seed":
      return "Use the function scope and coverage-seed rules documented for this tool; RE-MCP will not infer missing overlay or mode evidence.";
    case "ambiguous-reference-target":
      return "Provide enough canonical function-entry context to avoid ambiguous runtime ownership.";
    case "reference-target-not-runtime-addressable":
      return "Choose a runtime-mapped ARM9/ARM7 executable function entry.";
    case "output-bound-exceeded":
      return "Reduce function, call-site, proof-search, or CFG limits so the serialized result fits RE_MCP_MAX_OUTPUT_BYTES.";
    case "disassembly-backend-failure":
      return "Verify the packaged @alexaltea/capstone-js JavaScript/WASM assets and Node.js runtime, then retry the function-analysis request.";
    default:
      return "Inspect the Nintendo DS ROM and narrow the function-analysis request; RE-MCP will not guess through unresolved static evidence.";
  }
}

function outputBoundResult(operation: string) {
  return textResult({
    error: "Serialized NDS result exceeds RE_MCP_MAX_OUTPUT_BYTES",
    operation,
    category: "output-bound-exceeded",
    correctiveAction: correctiveAction("output-bound-exceeded"),
  }, true);
}

function boundedTextResult(
  config: ServerConfig,
  operation: string,
  value: unknown,
  isError = false,
) {
  const text = JSON.stringify(value, null, 2);
  if (!isError && Buffer.byteLength(text, "utf8") > config.maxOutputBytes) {
    return outputBoundResult(operation);
  }
  return textResultFromText(text, isError);
}

function functionErrorResult(
  config: ServerConfig,
  operation: string,
  error: unknown,
) {
  const category = error instanceof DisassemblyBackendError
    ? error.category
    : error instanceof NdsError
      ? String(error.category)
      : "invalid-rom";
  const message = error instanceof Error ? error.message : String(error);
  return boundedTextResult(config, operation, {
    error: message,
    operation,
    category,
    correctiveAction: correctiveAction(category),
  }, true);
}

function resolveRom(config: ServerConfig, rom: string): string {
  return resolveInside(config.workspaceRoot, rom);
}

export function registerNdsFunctionTools(
  server: McpServer,
  config: ServerConfig,
): void {
  server.tool(
    "nds_discover_functions",
    "Discover a bounded call graph of Nintendo DS ARM/Thumb function entries proven only by program-entry or deterministic resolved direct-call evidence.",
    {
      rom: romSchema,
      processor: processorSchema,
      scope: functionScopeSchema,
      seeds: z.array(functionSeedSchema).max(128).default([]),
      maxComponents: functionComponentLimitSchema,
      maxFunctions: functionLimitSchema,
      maxCallSites: functionCallSiteLimitSchema,
      maxTotalBlocks: functionBlockLimitSchema,
      maxTotalInstructions: functionInstructionLimitSchema,
      maxTotalBytes: functionByteLimitSchema,
      maxTotalEdges: functionEdgeLimitSchema,
      maxCfgBlocksPerFunction: cfgBlockLimitSchema,
      maxCfgInstructionsPerFunction: cfgInstructionLimitSchema,
      maxCfgBytesPerFunction: cfgByteLimitSchema,
      maxCfgEdgesPerFunction: cfgEdgeLimitSchema,
    },
    async ({
      rom,
      processor,
      scope,
      seeds,
      maxComponents,
      maxFunctions,
      maxCallSites,
      maxTotalBlocks,
      maxTotalInstructions,
      maxTotalBytes,
      maxTotalEdges,
      maxCfgBlocksPerFunction,
      maxCfgInstructionsPerFunction,
      maxCfgBytesPerFunction,
      maxCfgEdgesPerFunction,
    }) => {
      const operation = "nds_discover_functions";
      try {
        const map = await readNdsRomMap(resolveRom(config, rom));
        const backend = await createCapstoneArmBackend();
        try {
          const result = await discoverNdsFunctions(
            map,
            { processor, scope, seeds },
            {
              maxComponents,
              maxFunctions,
              maxCallSites,
              maxTotalBlocks,
              maxTotalInstructions,
              maxTotalBytes,
              maxTotalEdges,
              perFunctionCfg: {
                maxBlocks: maxCfgBlocksPerFunction,
                maxInstructions: maxCfgInstructionsPerFunction,
                maxBytes: maxCfgBytesPerFunction,
                maxEdges: maxCfgEdgesPerFunction,
              },
            },
            backend,
          );
          return boundedTextResult(config, operation, result);
        } finally {
          backend.close();
        }
      } catch (error) {
        return functionErrorResult(config, operation, error);
      }
    },
  );

  server.tool(
    "nds_analyze_function",
    "Prove one Nintendo DS ARM/Thumb function entry from program-entry or deterministic direct-call evidence, distinguish complete negative from inconclusive proof, and analyze its bounded CFG only when proven.",
    {
      rom: romSchema,
      processor: processorSchema,
      runtimeAddress: uint32Schema,
      mode: modeSchema,
      overlayId: uint32Schema.optional(),
      proofScope: functionScopeSchema,
      seeds: z.array(functionSeedSchema).max(128).default([]),
      maxProofComponents: proofComponentLimitSchema,
      maxProofBlocks: proofBlockLimitSchema,
      maxProofInstructions: proofInstructionLimitSchema,
      maxProofBytes: proofByteLimitSchema,
      maxProofEdges: proofEdgeLimitSchema,
      maxProofCallSites: proofCallSiteLimitSchema,
      maxCfgBlocks: cfgBlockLimitSchema,
      maxCfgInstructions: cfgInstructionLimitSchema,
      maxCfgBytes: cfgByteLimitSchema,
      maxCfgEdges: cfgEdgeLimitSchema,
    },
    async ({
      rom,
      processor,
      runtimeAddress,
      mode,
      overlayId,
      proofScope,
      seeds,
      maxProofComponents,
      maxProofBlocks,
      maxProofInstructions,
      maxProofBytes,
      maxProofEdges,
      maxProofCallSites,
      maxCfgBlocks,
      maxCfgInstructions,
      maxCfgBytes,
      maxCfgEdges,
    }) => {
      const operation = "nds_analyze_function";
      try {
        const map = await readNdsRomMap(resolveRom(config, rom));
        const backend = await createCapstoneArmBackend();
        try {
          const result = await analyzeNdsFunction(
            map,
            {
              processor,
              runtimeAddress,
              mode,
              ...(overlayId === undefined ? {} : { overlayId }),
              proofScope,
              seeds,
            },
            {
              proof: {
                maxComponents: maxProofComponents,
                maxBlocks: maxProofBlocks,
                maxInstructions: maxProofInstructions,
                maxBytes: maxProofBytes,
                maxEdges: maxProofEdges,
                maxXrefs: maxProofCallSites,
              },
              cfg: {
                maxBlocks: maxCfgBlocks,
                maxInstructions: maxCfgInstructions,
                maxBytes: maxCfgBytes,
                maxEdges: maxCfgEdges,
              },
            },
            backend,
          );
          return boundedTextResult(config, operation, result);
        } finally {
          backend.close();
        }
      } catch (error) {
        return functionErrorResult(config, operation, error);
      }
    },
  );
}
