import path from "node:path";

import { z } from "zod";

import type { ServerConfig } from "../config.js";
import { resolveInside } from "../security/path-policy.js";
import { DisassemblyBackendError } from "../services/disassembly/backend.js";
import { getDisassemblyBackend } from "../services/disassembly/capstone-backend.js";
import { analyzeNdsControlFlow } from "../services/nds/control-flow.js";
import { disassembleNdsRange } from "../services/nds/disassembly.js";
import {
  AnyNdsErrorCategory,
  NdsError,
  type NdsErrorCategory,
} from "../services/nds/errors.js";
import {
  extractNdsAnalysisBundle,
  extractNdsComponent,
} from "../services/nds/extraction.js";
import { analyzeNdsFunction } from "../services/nds/function-analysis.js";
import { discoverNdsFunctions } from "../services/nds/function-discovery.js";
import type { FunctionSearchScope } from "../services/nds/function-source.js";
import { listNdsReferences } from "../services/nds/reference-list.js";
import {
  resolveRomOffset,
  resolveRuntimeAddress,
} from "../services/nds/resolver.js";
import { readNdsRomMap } from "../services/nds/rom-map.js";
import { searchNdsPattern } from "../services/nds/search.js";
import type { NdsPatternScope } from "../services/nds/search-source.js";
import type {
  ReferenceSearchScope,
  ReferenceSearchSeed,
} from "../services/nds/xref-source.js";
import { findNdsXrefs } from "../services/nds/xrefs.js";

import type { RegisteredTool } from "./types.js";

const uint32Schema = z.number().int().min(0).max(0xffff_ffff);
const positiveSafeIntegerSchema = z.number().int().min(1).max(Number.MAX_SAFE_INTEGER);
const processorSchema = z.enum(["arm9", "arm7"]);
const modeSchema = z.enum(["arm", "thumb"]);
const referenceTargetSchema = z.union([
  z.object({
    targetRuntimeAddress: uint32Schema,
    targetRomOffset: z.never().optional(),
  }),
  z.object({
    targetRomOffset: uint32Schema,
    targetRuntimeAddress: z.never().optional(),
  }),
]);
const referenceScopeSchema = z.discriminatedUnion("kind", [
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
const referenceSeedSchema = z.object({
  runtimeAddress: uint32Schema,
  mode: z.enum(["arm", "thumb"]),
  overlayId: uint32Schema.optional(),
});

type NdsToolErrorCategory = AnyNdsErrorCategory | "disassembly-backend-failure";

function textResultFromText(text: string, isError = false) {
  return {
    content: [{ type: "text" as const, text }],
    isError,
  };
}

function textResult(value: unknown, isError = false) {
  return textResultFromText(JSON.stringify(value, null, 2), isError);
}

function correctiveAction(category: NdsToolErrorCategory): string {
  switch (category) {
    case "invalid-rom":
      return "Use a readable Nintendo DS ROM path inside RE_MCP_WORKSPACE_ROOT and re-run ROM inspection if the source changed.";
    case "malformed-header":
    case "malformed-fat":
    case "malformed-fnt":
    case "malformed-overlay-table":
      return "Inspect the ROM structure or use a known-good ROM revision; RE-MCP will not guess through malformed metadata.";
    case "range-out-of-bounds":
      return "Use an address, ROM offset, mode, or canonical component that lies inside the validated source ROM ranges and approved bounds.";
    case "unknown-file-id":
      return "List NitroFS files first, then use an existing file ID or exact parsed NitroFS path.";
    case "unknown-overlay-id":
      return "List overlays first, then use an existing overlay ID for the selected processor.";
    case "output-bound-exceeded":
      return "Narrow the request with prefix, processor, pagination, or smaller disassembly/CFG/reference limits.";
    case "generated-path-failure":
      return "Check workspace write permissions and retry; generated NDS output is restricted to analysis/generated/nds.";
    case "ambiguous-reference-target":
      return "Use a runtime address or a ROM offset that maps to exactly one runtime address for the selected processor.";
    case "reference-target-not-runtime-addressable":
      return "Choose a runtime-mapped ARM9/ARM7 target; ordinary structural/NitroFS ROM bytes are not reverse-xref targets in this milestone.";
    case "invalid-reference-scope":
      return "Choose main, existing overlay IDs for the selected processor, or all executable components without duplicate overlay IDs.";
    case "invalid-reference-seed":
      return "Use an aligned ARM/Thumb seed that resolves uniquely to selected uncompressed file-backed code.";
    case "reference-scan-limit-exceeded":
      return "Use valid positive bounded scan limits; internal reference-scan limit invariants must not be bypassed.";
    case "invalid-pattern":
      return "Use an exact bounded NDS pattern; byte signatures may contain only exact bytes and ?? whole-byte wildcards.";
    case "invalid-pattern-scope":
      return "Use whole-rom or select at least one existing canonical NDS component; arbitrary raw byte ranges are not accepted.";
    case "pattern-search-limit-exceeded":
      return "Keep NDS pattern length, selector counts, pagination, scan bytes, and context within the documented bounds.";
    case "invalid-function-scope":
      return "Choose main, existing overlay IDs, selected main plus overlays, or all executable components without duplicate overlay IDs.";
    case "invalid-function-seed":
      return "Use an aligned ARM/Thumb seed that resolves uniquely to selected uncompressed file-backed code; seeds provide coverage only and do not prove functions.";
    case "function-entry-not-uniquely-resolved":
      return "Provide processor, ARM/Thumb mode, and overlay context when needed so the requested function entry selects one exact initialized executable source.";
    case "function-discovery-limit-exceeded":
      return "Use positive bounded function-discovery, proof-search, and CFG limits within the documented maxima.";
    case "malformed-blz":
      return "Use a known-good ROM revision; RE-MCP will not analyze a canonically compressed overlay whose BLZ stream is malformed.";
    case "blz-output-size-mismatch":
      return "Verify the ROM revision and overlay metadata; decoded overlay bytes must exactly match the canonical initialized runtime size.";
    case "blz-output-limit":
      return "Use an overlay within RE-MCP's bounded compressed/decompressed size limits; decompression limits cannot be bypassed.";
    case "disassembly-backend-failure":
      return "Verify the packaged @alexaltea/capstone-js JavaScript/WASM assets and Node.js runtime, then retry the static disassembly request.";
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

function ndsErrorResult(
  config: ServerConfig,
  operation: string,
  error: unknown,
  fallbackCategory: NdsErrorCategory,
) {
  const category: NdsToolErrorCategory = error instanceof DisassemblyBackendError
    ? error.category
    : error instanceof NdsError
      ? error.category
      : fallbackCategory;
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

function relativeWorkspacePath(config: ServerConfig, absolutePath: string): string {
  return path.relative(config.workspaceRoot, absolutePath).split(path.sep).join("/");
}

const COMPONENT_SCHEMA = z.union([
  z.object({ kind: z.literal("arm9") }),
  z.object({ kind: z.literal("arm7") }),
  z.object({ kind: z.literal("file"), fileId: uint32Schema }),
  z.object({ kind: z.literal("overlay"), processor: processorSchema, overlayId: uint32Schema }),
]);

const LOCATION_SCHEMA = z.union([
  z.object({
    processor: processorSchema,
    runtimeAddress: uint32Schema,
    romOffset: z.never().optional(),
    overlayId: uint32Schema.optional(),
    mode: modeSchema.optional(),
  }),
  z.object({
    romOffset: uint32Schema,
    runtimeAddress: z.never().optional(),
    processor: processorSchema.optional(),
    overlayId: uint32Schema.optional(),
    mode: modeSchema.optional(),
  }),
]);

const PATTERN_SCOPE_SCHEMA = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("whole-rom") }),
  z.object({
    kind: z.literal("components"),
    components: z.array(COMPONENT_SCHEMA).min(1).max(128),
  }),
]);

const FUNCTION_SCOPE_SCHEMA = z.discriminatedUnion("kind", [
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

export function registerNdsTools(config: ServerConfig): RegisteredTool[] {
  const tools: RegisteredTool[] = [
    {
      name: "nds_inspect_rom",
      description: "Inspect a Nintendo DS ROM and return its validated canonical map.",
      schema: z.object({ rom: z.string().min(1) }),
      handler: async ({ rom }) => {
        try {
          const map = await readNdsRomMap(resolveRom(config, rom));
          return boundedTextResult(config, "nds_inspect_rom", map);
        } catch (error) {
          return ndsErrorResult(config, "nds_inspect_rom", error, "invalid-rom");
        }
      },
    },
    {
      name: "nds_list_files",
      description: "List validated NitroFS files in a Nintendo DS ROM.",
      schema: z.object({ rom: z.string().min(1), prefix: z.string().optional() }),
      handler: async ({ rom, prefix }) => {
        try {
          const map = await readNdsRomMap(resolveRom(config, rom));
          const files = map.filesystem.files
            .filter((file) => prefix === undefined || file.path.startsWith(prefix))
            .map((file) => ({
              id: file.id,
              path: file.path,
              romOffset: file.romOffset,
              size: file.size,
            }));
          return boundedTextResult(config, "nds_list_files", files);
        } catch (error) {
          return ndsErrorResult(config, "nds_list_files", error, "invalid-rom");
        }
      },
    },
    {
      name: "nds_list_overlays",
      description: "List validated ARM9/ARM7 overlay metadata in a Nintendo DS ROM.",
      schema: z.object({ rom: z.string().min(1), processor: processorSchema.optional() }),
      handler: async ({ rom, processor }) => {
        try {
          const map = await readNdsRomMap(resolveRom(config, rom));
          const overlays = processor === undefined
            ? [...map.overlays.arm9, ...map.overlays.arm7]
            : map.overlays[processor];
          return boundedTextResult(config, "nds_list_overlays", overlays);
        } catch (error) {
          return ndsErrorResult(config, "nds_list_overlays", error, "invalid-rom");
        }
      },
    },
    {
      name: "nds_resolve_runtime_address",
      description: "Resolve a canonical ARM9/ARM7 runtime address without guessing through overlay ambiguity.",
      schema: z.object({
        rom: z.string().min(1),
        runtimeAddress: uint32Schema,
        processor: processorSchema.optional(),
      }),
      handler: async ({ rom, runtimeAddress, processor }) => {
        try {
          const map = await readNdsRomMap(resolveRom(config, rom));
          const result = resolveRuntimeAddress(map, runtimeAddress, processor);
          return boundedTextResult(config, "nds_resolve_runtime_address", result);
        } catch (error) {
          return ndsErrorResult(config, "nds_resolve_runtime_address", error, "range-out-of-bounds");
        }
      },
    },
    {
      name: "nds_resolve_rom_offset",
      description: "Resolve a validated physical Nintendo DS ROM offset to its canonical structural/runtime owners.",
      schema: z.object({ rom: z.string().min(1), romOffset: uint32Schema }),
      handler: async ({ rom, romOffset }) => {
        try {
          const map = await readNdsRomMap(resolveRom(config, rom));
          const result = resolveRomOffset(map, romOffset);
          return boundedTextResult(config, "nds_resolve_rom_offset", result);
        } catch (error) {
          return ndsErrorResult(config, "nds_resolve_rom_offset", error, "range-out-of-bounds");
        }
      },
    },
    {
      name: "nds_extract_component",
      description: "Extract one canonical NDS main processor image, NitroFS file, or overlay into deterministic generated analysis output.",
      schema: z.object({
        rom: z.string().min(1),
        component: COMPONENT_SCHEMA,
      }),
      handler: async ({ rom, component }) => {
        try {
          const map = await readNdsRomMap(resolveRom(config, rom));
          const output = await extractNdsComponent(map, component, config.workspaceRoot);
          return boundedTextResult(config, "nds_extract_component", {
            ...output,
            output: relativeWorkspacePath(config, output.output),
          });
        } catch (error) {
          return ndsErrorResult(config, "nds_extract_component", error, "generated-path-failure");
        }
      },
    },
    {
      name: "nds_extract_analysis_bundle",
      description: "Extract a transactional, deterministic static-analysis bundle for a validated Nintendo DS ROM.",
      schema: z.object({ rom: z.string().min(1) }),
      handler: async ({ rom }) => {
        try {
          const map = await readNdsRomMap(resolveRom(config, rom));
          const output = await extractNdsAnalysisBundle(map, config.workspaceRoot);
          return boundedTextResult(config, "nds_extract_analysis_bundle", {
            ...output,
            output: relativeWorkspacePath(config, output.output),
          });
        } catch (error) {
          return ndsErrorResult(config, "nds_extract_analysis_bundle", error, "generated-path-failure");
        }
      },
    },
    {
      name: "nds_disassemble_range",
      description: "Disassemble a bounded canonical Nintendo DS ARM/Thumb range using the packaged Capstone backend.",
      schema: z.object({
        rom: z.string().min(1),
        location: LOCATION_SCHEMA,
        maxInstructions: positiveSafeIntegerSchema.max(4096),
        maxBytes: positiveSafeIntegerSchema.max(64 * 1024),
      }),
      handler: async ({ rom, location, maxInstructions, maxBytes }) => {
        try {
          const map = await readNdsRomMap(resolveRom(config, rom));
          const backend = await getDisassemblyBackend();
          const result = await disassembleNdsRange(
            map,
            location,
            { maxInstructions, maxBytes },
            backend,
          );
          return boundedTextResult(config, "nds_disassemble_range", result);
        } catch (error) {
          return ndsErrorResult(config, "nds_disassemble_range", error, "range-out-of-bounds");
        }
      },
    },
    {
      name: "nds_analyze_control_flow",
      description: "Build a bounded canonical ARM/Thumb control-flow graph without pretending indirect edges are resolved.",
      schema: z.object({
        rom: z.string().min(1),
        location: LOCATION_SCHEMA,
        maxBlocks: positiveSafeIntegerSchema.max(1024),
        maxInstructions: positiveSafeIntegerSchema.max(16_384),
        maxBytes: positiveSafeIntegerSchema.max(512 * 1024),
        maxEdges: positiveSafeIntegerSchema.max(4096),
      }),
      handler: async ({ rom, location, maxBlocks, maxInstructions, maxBytes, maxEdges }) => {
        try {
          const map = await readNdsRomMap(resolveRom(config, rom));
          const backend = await getDisassemblyBackend();
          const result = await analyzeNdsControlFlow(
            map,
            location,
            { maxBlocks, maxInstructions, maxBytes, maxEdges },
            backend,
          );
          return boundedTextResult(config, "nds_analyze_control_flow", result);
        } catch (error) {
          return ndsErrorResult(config, "nds_analyze_control_flow", error, "range-out-of-bounds");
        }
      },
    },
    {
      name: "nds_list_references",
      description: "List deterministic static references from one bounded canonical Nintendo DS disassembly range.",
      schema: z.object({
        rom: z.string().min(1),
        location: LOCATION_SCHEMA,
        maxInstructions: positiveSafeIntegerSchema.max(4096),
        maxBytes: positiveSafeIntegerSchema.max(64 * 1024),
        maxReferences: positiveSafeIntegerSchema.max(8192),
      }),
      handler: async ({ rom, location, maxInstructions, maxBytes, maxReferences }) => {
        try {
          const map = await readNdsRomMap(resolveRom(config, rom));
          const backend = await getDisassemblyBackend();
          const result = await listNdsReferences(
            map,
            location,
            { maxInstructions, maxBytes, maxReferences },
            backend,
          );
          return boundedTextResult(config, "nds_list_references", result);
        } catch (error) {
          return ndsErrorResult(config, "nds_list_references", error, "range-out-of-bounds");
        }
      },
    },
    {
      name: "nds_find_xrefs",
      description: "Find bounded deterministic static xrefs to one canonical ARM9/ARM7 runtime target with explicit executable-component coverage.",
      schema: z.object({
        rom: z.string().min(1),
        processor: processorSchema,
        target: referenceTargetSchema,
        scope: referenceScopeSchema,
        seeds: z.array(referenceSeedSchema).max(256).default([]),
        maxComponents: positiveSafeIntegerSchema.max(256),
        maxBlocks: positiveSafeIntegerSchema.max(4096),
        maxInstructions: positiveSafeIntegerSchema.max(65_536),
        maxBytes: positiveSafeIntegerSchema.max(4 * 1024 * 1024),
        maxEdges: positiveSafeIntegerSchema.max(16_384),
        maxXrefs: positiveSafeIntegerSchema.max(16_384),
      }),
      handler: async ({
        rom,
        processor,
        target,
        scope,
        seeds,
        maxComponents,
        maxBlocks,
        maxInstructions,
        maxBytes,
        maxEdges,
        maxXrefs,
      }) => {
        try {
          const map = await readNdsRomMap(resolveRom(config, rom));
          const backend = await getDisassemblyBackend();
          const result = await findNdsXrefs(
            map,
            {
              processor,
              target,
              scope: scope as ReferenceSearchScope,
              seeds: seeds as readonly ReferenceSearchSeed[],
            },
            {
              maxComponents,
              maxBlocks,
              maxInstructions,
              maxBytes,
              maxEdges,
              maxXrefs,
            },
            backend,
          );
          return boundedTextResult(config, "nds_find_xrefs", result);
        } catch (error) {
          return ndsErrorResult(config, "nds_find_xrefs", error, "range-out-of-bounds");
        }
      },
    },
    {
      name: "nds_search_pattern",
      description: "Search bounded canonical Nintendo DS ROM bytes with exact/wildcard byte or UTF-8 patterns and explicit scope.",
      schema: z.object({
        rom: z.string().min(1),
        pattern: z.union([
          z.object({ kind: z.literal("bytes"), value: z.string().min(1) }),
          z.object({ kind: z.literal("utf8"), value: z.string().min(1) }),
        ]),
        scope: PATTERN_SCOPE_SCHEMA,
        alignment: z.number().int().min(1).max(4096).default(1),
        offset: z.number().int().min(0).max(1_000_000).default(0),
        limit: z.number().int().min(1).max(10_000).default(100),
        contextBefore: z.number().int().min(0).max(256).default(0),
        contextAfter: z.number().int().min(0).max(256).default(0),
        maxScanBytes: positiveSafeIntegerSchema.max(256 * 1024 * 1024).default(64 * 1024 * 1024),
      }),
      handler: async ({
        rom,
        pattern,
        scope,
        alignment,
        offset,
        limit,
        contextBefore,
        contextAfter,
        maxScanBytes,
      }) => {
        try {
          const map = await readNdsRomMap(resolveRom(config, rom));
          const result = await searchNdsPattern(
            map,
            pattern,
            scope as NdsPatternScope,
            {
              alignment,
              offset,
              limit,
              contextBefore,
              contextAfter,
              maxScanBytes,
            },
          );
          return boundedTextResult(config, "nds_search_pattern", result);
        } catch (error) {
          return ndsErrorResult(config, "nds_search_pattern", error, "invalid-pattern");
        }
      },
    },
    {
      name: "nds_discover_functions",
      description: "Discover bounded proven ARM/Thumb function entries from program entry and exact direct-call evidence, with explicit coverage accounting.",
      schema: z.object({
        rom: z.string().min(1),
        processor: processorSchema,
        scope: FUNCTION_SCOPE_SCHEMA,
        seeds: z.array(referenceSeedSchema).max(256).default([]),
        maxComponents: positiveSafeIntegerSchema.max(256),
        maxFunctions: positiveSafeIntegerSchema.max(8192),
        maxBlocks: positiveSafeIntegerSchema.max(65_536),
        maxInstructions: positiveSafeIntegerSchema.max(1_000_000),
        maxBytes: positiveSafeIntegerSchema.max(64 * 1024 * 1024),
        maxEdges: positiveSafeIntegerSchema.max(1_000_000),
        maxCalls: positiveSafeIntegerSchema.max(1_000_000),
        maxProofSearchFunctions: positiveSafeIntegerSchema.max(8192),
      }),
      handler: async ({
        rom,
        processor,
        scope,
        seeds,
        maxComponents,
        maxFunctions,
        maxBlocks,
        maxInstructions,
        maxBytes,
        maxEdges,
        maxCalls,
        maxProofSearchFunctions,
      }) => {
        try {
          const map = await readNdsRomMap(resolveRom(config, rom));
          const backend = await getDisassemblyBackend();
          const result = await discoverNdsFunctions(
            map,
            {
              processor,
              scope: scope as FunctionSearchScope,
              seeds: seeds as readonly ReferenceSearchSeed[],
            },
            {
              maxComponents,
              maxFunctions,
              maxBlocks,
              maxInstructions,
              maxBytes,
              maxEdges,
              maxCalls,
              maxProofSearchFunctions,
            },
            backend,
          );
          return boundedTextResult(config, "nds_discover_functions", result);
        } catch (error) {
          return ndsErrorResult(config, "nds_discover_functions", error, "range-out-of-bounds");
        }
      },
    },
    {
      name: "nds_analyze_function",
      description: "Analyze one proven ARM/Thumb function entry with bounded proof search, CFG-backed body, calls, inbound references, and explicit negative-claim integrity.",
      schema: z.object({
        rom: z.string().min(1),
        processor: processorSchema,
        runtimeAddress: uint32Schema,
        mode: modeSchema,
        overlayId: uint32Schema.nullish(),
        maxComponents: positiveSafeIntegerSchema.max(256),
        maxFunctions: positiveSafeIntegerSchema.max(8192),
        maxBlocks: positiveSafeIntegerSchema.max(65_536),
        maxInstructions: positiveSafeIntegerSchema.max(1_000_000),
        maxBytes: positiveSafeIntegerSchema.max(64 * 1024 * 1024),
        maxEdges: positiveSafeIntegerSchema.max(1_000_000),
        maxCalls: positiveSafeIntegerSchema.max(1_000_000),
        maxProofSearchFunctions: positiveSafeIntegerSchema.max(8192),
      }),
      handler: async ({
        rom,
        processor,
        runtimeAddress,
        mode,
        overlayId,
        maxComponents,
        maxFunctions,
        maxBlocks,
        maxInstructions,
        maxBytes,
        maxEdges,
        maxCalls,
        maxProofSearchFunctions,
      }) => {
        try {
          const map = await readNdsRomMap(resolveRom(config, rom));
          const backend = await getDisassemblyBackend();
          const result = await analyzeNdsFunction(
            map,
            {
              processor,
              runtimeAddress,
              mode,
              overlayId: overlayId ?? null,
            },
            {
              maxComponents,
              maxFunctions,
              maxBlocks,
              maxInstructions,
              maxBytes,
              maxEdges,
              maxCalls,
              maxProofSearchFunctions,
            },
            backend,
          );
          return boundedTextResult(config, "nds_analyze_function", result);
        } catch (error) {
          return ndsErrorResult(config, "nds_analyze_function", error, "function-entry-not-uniquely-resolved");
        }
      },
    },
  ];

  return tools;
}
