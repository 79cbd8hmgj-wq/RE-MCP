import path from "node:path";

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

import type { ServerConfig } from "../config.js";
import { resolveInside } from "../security/paths.js";
import {
  DisassemblyBackendError,
} from "../services/disassembly/backend.js";
import { createCapstoneArmBackend } from "../services/disassembly/capstone.js";
import { analyzeNdsControlFlow } from "../services/nds/control-flow.js";
import { disassembleNdsRange } from "../services/nds/disassembly.js";
import type { NdsDisassemblyLocation } from "../services/nds/disassembly-source.js";
import { NdsError, type NdsErrorCategory } from "../services/nds/errors.js";
import {
  extractNdsAnalysisBundle,
  extractNdsComponent,
  type NdsExtractionRequest,
} from "../services/nds/extraction.js";
import {
  resolveRomOffset,
  resolveRuntimeAddress,
} from "../services/nds/resolver.js";
import { readNdsRomMap } from "../services/nds/rom-map.js";

const romSchema = z.string().min(1);
const uint32Schema = z.number().int().min(0).max(0xffffffff);
const processorSchema = z.enum(["arm9", "arm7"]);
const listProcessorSchema = z.enum(["arm9", "arm7", "all"]);
const listLimitSchema = z.number().int().min(1).max(200).default(100);
const listOffsetSchema = z.number().int().min(0).default(0);
const disassemblyModeSchema = z.enum(["arm", "thumb", "auto"]);
const linearInstructionLimitSchema = z.number().int().min(1).max(256).default(32);
const linearByteLimitSchema = z.number().int().min(2).max(1024).default(128);
const cfgBlockLimitSchema = z.number().int().min(1).max(256).default(64);
const cfgInstructionLimitSchema = z.number().int().min(1).max(4096).default(512);
const cfgByteLimitSchema = z.number().int().min(2).max(16384).default(2048);
const cfgEdgeLimitSchema = z.number().int().min(1).max(1024).default(128);

type NdsToolErrorCategory = NdsErrorCategory | "disassembly-backend-failure";

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
      return "Narrow the request with prefix, processor, pagination, or smaller disassembly/CFG limits.";
    case "generated-path-failure":
      return "Check workspace write permissions and retry; generated NDS output is restricted to analysis/generated/nds.";
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

function normalizeExtractionRequest(input: {
  readonly component: "arm9" | "arm7" | "arm9-overlay" | "arm7-overlay" | "nitrofs-file";
  readonly overlayId?: number;
  readonly fileId?: number;
  readonly filePath?: string;
}): NdsExtractionRequest {
  const hasOverlay = input.overlayId !== undefined;
  const hasFileId = input.fileId !== undefined;
  const hasFilePath = input.filePath !== undefined;

  if (input.component === "arm9" || input.component === "arm7") {
    if (hasOverlay || hasFileId || hasFilePath) {
      throw new Error(`${input.component} extraction does not accept overlayId, fileId, or filePath selectors`);
    }
    return { component: input.component };
  }

  if (input.component === "arm9-overlay" || input.component === "arm7-overlay") {
    if (!hasOverlay || hasFileId || hasFilePath) {
      throw new Error(`${input.component} extraction requires exactly overlayId and no file selector`);
    }
    return { component: input.component, overlayId: input.overlayId! };
  }

  if (hasOverlay || hasFileId === hasFilePath) {
    throw new Error("nitrofs-file extraction requires exactly one of fileId or filePath");
  }
  if (hasFileId) {
    return { component: "nitrofs-file", fileId: input.fileId! };
  }
  return { component: "nitrofs-path", filePath: input.filePath! };
}

function normalizeDisassemblyLocation(input: {
  readonly processor: "arm9" | "arm7";
  readonly mode: "arm" | "thumb" | "auto";
  readonly runtimeAddress?: number;
  readonly romOffset?: number;
  readonly overlayId?: number;
}): NdsDisassemblyLocation {
  const hasRuntime = input.runtimeAddress !== undefined;
  const hasRom = input.romOffset !== undefined;
  if (hasRuntime === hasRom) {
    throw new NdsError(
      "range-out-of-bounds",
      "Disassembly requires exactly one of runtimeAddress or romOffset",
    );
  }
  return {
    processor: input.processor,
    mode: input.mode,
    ...(hasRuntime
      ? { runtimeAddress: input.runtimeAddress! }
      : { romOffset: input.romOffset! }),
    ...(input.overlayId === undefined ? {} : { overlayId: input.overlayId }),
  };
}

export function registerNdsTools(server: McpServer, config: ServerConfig): void {
  server.tool(
    "nds_inspect_rom",
    "Parse a Nintendo DS ROM into the canonical static structure summary without modifying it.",
    { rom: romSchema },
    async ({ rom }) => {
      const operation = "nds_inspect_rom";
      try {
        const romPath = resolveRom(config, rom);
        const map = await readNdsRomMap(romPath);
        return boundedTextResult(config, operation, {
          rom: relativeWorkspacePath(config, map.romPath),
          sha256: map.sha256,
          sha256Prefix: map.sha256Prefix,
          fileSize: map.fileSize,
          game: {
            title: map.header.gameTitle,
            code: map.header.gameCode,
            makerCode: map.header.makerCode,
            unitCode: map.header.unitCode,
            deviceCapacity: map.header.deviceCapacity,
            romVersion: map.header.romVersion,
          },
          arm9: map.header.arm9,
          arm7: map.header.arm7,
          fnt: map.header.fnt,
          fat: map.header.fat,
          arm9OverlayTable: map.header.arm9OverlayTable,
          arm7OverlayTable: map.header.arm7OverlayTable,
          bannerOffset: map.header.bannerOffset,
          nitroFsFileCount: map.filesystem.files.length,
          arm9OverlayCount: map.overlays.arm9.length,
          arm7OverlayCount: map.overlays.arm7.length,
          executableRanges: map.executableRanges,
        });
      } catch (error) {
        return ndsErrorResult(config, operation, error, "invalid-rom");
      }
    },
  );

  server.tool(
    "nds_list_files",
    "List bounded NitroFS/FAT file mappings from the canonical NDS model.",
    {
      rom: romSchema,
      prefix: z.string().max(4096).default(""),
      limit: listLimitSchema,
      offset: listOffsetSchema,
    },
    async ({ rom, prefix, limit, offset }) => {
      const operation = "nds_list_files";
      try {
        const map = await readNdsRomMap(resolveRom(config, rom));
        const filtered = prefix.length === 0
          ? [...map.filesystem.files]
          : map.filesystem.files.filter(
            (file) => file.path !== null && file.path.startsWith(prefix),
          );
        filtered.sort((left, right) => left.fileId - right.fileId);
        const page = filtered.slice(offset, offset + limit);
        const nextOffset = offset + page.length < filtered.length
          ? offset + page.length
          : null;
        return boundedTextResult(config, operation, {
          total: filtered.length,
          offset,
          limit,
          nextOffset,
          files: page.map((file) => ({
            fileId: file.fileId,
            path: file.path,
            romOffset: file.startOffset,
            endOffset: file.endOffset,
            size: file.size,
          })),
        });
      } catch (error) {
        return ndsErrorResult(config, operation, error, "invalid-rom");
      }
    },
  );

  server.tool(
    "nds_list_overlays",
    "List bounded ARM9/ARM7 overlay metadata without claiming runtime loaded state.",
    {
      rom: romSchema,
      processor: listProcessorSchema.default("all"),
      limit: listLimitSchema,
      offset: listOffsetSchema,
    },
    async ({ rom, processor, limit, offset }) => {
      const operation = "nds_list_overlays";
      try {
        const map = await readNdsRomMap(resolveRom(config, rom));
        const overlays = processor === "arm9"
          ? [...map.overlays.arm9]
          : processor === "arm7"
            ? [...map.overlays.arm7]
            : [...map.overlays.arm9, ...map.overlays.arm7];
        overlays.sort((left, right) => {
          if (left.processor !== right.processor) return left.processor === "arm9" ? -1 : 1;
          return left.overlayId - right.overlayId;
        });
        const page = overlays.slice(offset, offset + limit);
        const nextOffset = offset + page.length < overlays.length
          ? offset + page.length
          : null;
        return boundedTextResult(config, operation, {
          total: overlays.length,
          offset,
          limit,
          nextOffset,
          overlays: page,
        });
      } catch (error) {
        return ndsErrorResult(config, operation, error, "invalid-rom");
      }
    },
  );

  server.tool(
    "nds_resolve_runtime_address",
    "Resolve one ARM9/ARM7 runtime address against main code and static overlay candidates without guessing overlap state.",
    {
      rom: romSchema,
      address: uint32Schema,
      processor: processorSchema,
    },
    async ({ rom, address, processor }) => {
      const operation = "nds_resolve_runtime_address";
      try {
        const map = await readNdsRomMap(resolveRom(config, rom));
        return boundedTextResult(
          config,
          operation,
          resolveRuntimeAddress(map, address, processor),
        );
      } catch (error) {
        return ndsErrorResult(config, operation, error, "invalid-rom");
      }
    },
  );

  server.tool(
    "nds_resolve_rom_offset",
    "Classify one ROM offset across NDS structural, file, main-binary, and overlay relationships.",
    {
      rom: romSchema,
      offset: uint32Schema,
    },
    async ({ rom, offset }) => {
      const operation = "nds_resolve_rom_offset";
      try {
        const map = await readNdsRomMap(resolveRom(config, rom));
        return boundedTextResult(config, operation, resolveRomOffset(map, offset));
      } catch (error) {
        return ndsErrorResult(config, operation, error, "invalid-rom");
      }
    },
  );

  server.tool(
    "nds_extract_component",
    "Extract one validated ARM9, ARM7, overlay, or NitroFS component to the server-controlled generated-analysis tree.",
    {
      rom: romSchema,
      component: z.enum(["arm9", "arm7", "arm9-overlay", "arm7-overlay", "nitrofs-file"]),
      overlayId: uint32Schema.optional(),
      fileId: uint32Schema.optional(),
      filePath: z.string().min(1).max(4096).optional(),
    },
    async ({ rom, component, overlayId, fileId, filePath }) => {
      const operation = "nds_extract_component";
      try {
        const request = normalizeExtractionRequest({
          component,
          ...(overlayId === undefined ? {} : { overlayId }),
          ...(fileId === undefined ? {} : { fileId }),
          ...(filePath === undefined ? {} : { filePath }),
        });
        const map = await readNdsRomMap(resolveRom(config, rom));
        const result = await extractNdsComponent(map, config.workspaceRoot, request);
        return boundedTextResult(config, operation, result);
      } catch (error) {
        return ndsErrorResult(config, operation, error, "generated-path-failure");
      }
    },
  );

  server.tool(
    "nds_extract_analysis_bundle",
    "Generate the deterministic NDS static-analysis bundle without dumping every NitroFS asset.",
    { rom: romSchema },
    async ({ rom }) => {
      const operation = "nds_extract_analysis_bundle";
      try {
        const map = await readNdsRomMap(resolveRom(config, rom));
        const result = await extractNdsAnalysisBundle(map, config.workspaceRoot);
        return boundedTextResult(config, operation, result);
      } catch (error) {
        return ndsErrorResult(config, operation, error, "generated-path-failure");
      }
    },
  );

  server.tool(
    "nds_disassemble_range",
    "Decode a bounded ARM/Thumb instruction window from one uniquely mapped Nintendo DS code source.",
    {
      rom: romSchema,
      processor: processorSchema,
      runtimeAddress: uint32Schema.optional(),
      romOffset: uint32Schema.optional(),
      overlayId: uint32Schema.optional(),
      mode: disassemblyModeSchema.default("auto"),
      maxInstructions: linearInstructionLimitSchema,
      maxBytes: linearByteLimitSchema,
    },
    async ({
      rom,
      processor,
      runtimeAddress,
      romOffset,
      overlayId,
      mode,
      maxInstructions,
      maxBytes,
    }) => {
      const operation = "nds_disassemble_range";
      try {
        const location = normalizeDisassemblyLocation({
          processor,
          mode,
          ...(runtimeAddress === undefined ? {} : { runtimeAddress }),
          ...(romOffset === undefined ? {} : { romOffset }),
          ...(overlayId === undefined ? {} : { overlayId }),
        });
        const map = await readNdsRomMap(resolveRom(config, rom));
        const backend = await createCapstoneArmBackend();
        try {
          const result = await disassembleNdsRange(
            map,
            location,
            { maxInstructions, maxBytes },
            backend,
          );
          return boundedTextResult(config, operation, result);
        } finally {
          backend.close();
        }
      } catch (error) {
        return ndsErrorResult(config, operation, error, "invalid-rom");
      }
    },
  );

  server.tool(
    "nds_analyze_control_flow",
    "Build a bounded direct-control-flow graph from one uniquely mapped Nintendo DS ARM/Thumb entry point without traversing calls.",
    {
      rom: romSchema,
      processor: processorSchema,
      runtimeAddress: uint32Schema.optional(),
      romOffset: uint32Schema.optional(),
      overlayId: uint32Schema.optional(),
      mode: disassemblyModeSchema.default("auto"),
      maxBlocks: cfgBlockLimitSchema,
      maxInstructions: cfgInstructionLimitSchema,
      maxBytes: cfgByteLimitSchema,
      maxEdges: cfgEdgeLimitSchema,
    },
    async ({
      rom,
      processor,
      runtimeAddress,
      romOffset,
      overlayId,
      mode,
      maxBlocks,
      maxInstructions,
      maxBytes,
      maxEdges,
    }) => {
      const operation = "nds_analyze_control_flow";
      try {
        const location = normalizeDisassemblyLocation({
          processor,
          mode,
          ...(runtimeAddress === undefined ? {} : { runtimeAddress }),
          ...(romOffset === undefined ? {} : { romOffset }),
          ...(overlayId === undefined ? {} : { overlayId }),
        });
        const map = await readNdsRomMap(resolveRom(config, rom));
        const backend = await createCapstoneArmBackend();
        try {
          const result = await analyzeNdsControlFlow(
            map,
            location,
            { maxBlocks, maxInstructions, maxBytes, maxEdges },
            backend,
          );
          return boundedTextResult(config, operation, result);
        } finally {
          backend.close();
        }
      } catch (error) {
        return ndsErrorResult(config, operation, error, "invalid-rom");
      }
    },
  );
}
