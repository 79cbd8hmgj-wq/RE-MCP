import path from "node:path";

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

import type { ServerConfig } from "../config.js";
import { resolveInside } from "../security/paths.js";
import {
  NdsError,
  type NdsErrorCategory,
  type NdsPatternSearchErrorCategory,
} from "../services/nds/errors.js";
import { searchNdsPattern } from "../services/nds/pattern-search.js";
import { readNdsRomMap } from "../services/nds/rom-map.js";

const romSchema = z.string().min(1);
const uint32Schema = z.number().int().min(0).max(0xffffffff);

const patternSchema = z.discriminatedUnion("kind", [
  z.object({
    kind: z.literal("byte-signature"),
    signature: z.string().min(1),
  }),
  z.object({
    kind: z.literal("integer"),
    value: z.number().int(),
    width: z.union([z.literal(8), z.literal(16), z.literal(32)]),
    endian: z.enum(["little", "big"]),
    signed: z.boolean(),
    alignment: z.union([z.literal(1), z.literal(2), z.literal(4)]).optional(),
  }),
  z.object({
    kind: z.literal("ascii"),
    text: z.string().min(1),
  }),
  z.object({
    kind: z.literal("utf16le"),
    text: z.string().min(1),
  }),
]);

const patternScopeSchema = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("whole-rom") }),
  z.object({
    kind: z.literal("components"),
    arm9Main: z.boolean().optional(),
    arm7Main: z.boolean().optional(),
    arm9OverlayIds: z.array(uint32Schema).max(128).optional(),
    arm7OverlayIds: z.array(uint32Schema).max(128).optional(),
    nitroFsFileIds: z.array(uint32Schema).max(256).optional(),
    nitroFsPaths: z.array(z.string().min(1).max(4096)).max(256).optional(),
  }),
]);

const offsetSchema = z.number().int().min(0).max(99999).default(0);
const limitSchema = z.number().int().min(1).max(1000).default(100);
const maxScanBytesSchema = z.number()
  .int()
  .min(1)
  .max(512 * 1024 * 1024)
  .default(64 * 1024 * 1024);
const contextBytesSchema = z.number().int().min(0).max(64).default(0);

type NdsPatternToolErrorCategory =
  | NdsErrorCategory
  | NdsPatternSearchErrorCategory;

function textResultFromText(text: string, isError = false) {
  return {
    content: [{ type: "text" as const, text }],
    isError,
  };
}

function textResult(value: unknown, isError = false) {
  return textResultFromText(JSON.stringify(value, null, 2), isError);
}

function correctiveAction(category: NdsPatternToolErrorCategory): string {
  switch (category) {
    case "invalid-rom":
      return "Use a readable Nintendo DS ROM path inside RE_MCP_WORKSPACE_ROOT and re-run ROM inspection if the source changed.";
    case "malformed-header":
    case "malformed-fat":
    case "malformed-fnt":
    case "malformed-overlay-table":
      return "Inspect the ROM structure or use a known-good ROM revision; RE-MCP will not guess through malformed metadata.";
    case "range-out-of-bounds":
      return "Use canonical NDS components whose validated physical ranges lie inside the source ROM.";
    case "unknown-file-id":
      return "List NitroFS files first, then use an existing file ID or exact parsed NitroFS path.";
    case "unknown-overlay-id":
      return "List overlays first, then use an existing overlay ID for the selected processor.";
    case "output-bound-exceeded":
      return "Reduce the result limit or contextBytes, narrow the component scope, or use a more selective pattern.";
    case "generated-path-failure":
      return "Check workspace permissions; pattern search itself does not create generated output paths.";
    case "invalid-pattern":
      return "Use one exact byte signature with optional ?? whole-byte wildcards, a bounded typed integer, exact ASCII, or exact UTF-16LE pattern.";
    case "invalid-pattern-scope":
      return "Choose whole-rom or select at least one existing ARM9/ARM7 main, overlay, or NitroFS component without arbitrary byte ranges.";
    case "pattern-search-limit-exceeded":
      return "Keep pattern length, selector counts, result pagination, scan bytes, and context within the documented NDS pattern-search bounds.";
  }
}

function isPatternToolErrorCategory(
  value: string,
): value is NdsPatternToolErrorCategory {
  switch (value) {
    case "invalid-rom":
    case "malformed-header":
    case "range-out-of-bounds":
    case "malformed-fat":
    case "malformed-fnt":
    case "malformed-overlay-table":
    case "unknown-file-id":
    case "unknown-overlay-id":
    case "output-bound-exceeded":
    case "generated-path-failure":
    case "invalid-pattern":
    case "invalid-pattern-scope":
    case "pattern-search-limit-exceeded":
      return true;
    default:
      return false;
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

function errorResult(
  config: ServerConfig,
  operation: string,
  error: unknown,
) {
  const rawCategory = error instanceof NdsError
    ? String(error.category)
    : "invalid-rom";
  const category: NdsPatternToolErrorCategory = isPatternToolErrorCategory(rawCategory)
    ? rawCategory
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

function relativeWorkspacePath(config: ServerConfig, absolutePath: string): string {
  return path.relative(config.workspaceRoot, absolutePath).split(path.sep).join("/");
}

export function registerNdsPatternTools(
  server: McpServer,
  config: ServerConfig,
): void {
  server.tool(
    "nds_search_pattern",
    "Search one bounded exact/wildcard byte signature, typed integer, ASCII string, or UTF-16LE string in a validated Nintendo DS ROM without mutation or heuristic inference.",
    {
      rom: romSchema,
      pattern: patternSchema,
      scope: patternScopeSchema,
      offset: offsetSchema,
      limit: limitSchema,
      maxScanBytes: maxScanBytesSchema,
      contextBytes: contextBytesSchema,
    },
    async ({
      rom,
      pattern,
      scope,
      offset,
      limit,
      maxScanBytes,
      contextBytes,
    }) => {
      const operation = "nds_search_pattern";
      try {
        const map = await readNdsRomMap(resolveRom(config, rom));
        const result = await searchNdsPattern(map, pattern, scope, {
          offset,
          limit,
          maxScanBytes,
          contextBytes,
        });
        return boundedTextResult(config, operation, {
          rom: relativeWorkspacePath(config, map.romPath),
          sha256: map.sha256,
          ...result,
        });
      } catch (error) {
        return errorResult(config, operation, error);
      }
    },
  );
}
