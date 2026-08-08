import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

import type { ServerConfig } from "../config.js";
import { resolveInside } from "../security/paths.js";
import { NdsError } from "../services/nds/errors.js";
import {
  decompileNdsGhidraFunction,
  inspectNdsGhidraFunction,
  listNdsGhidraCalls,
  listNdsGhidraReferences,
  searchNdsGhidraSymbols,
} from "../services/nds/ghidra-inspection.js";
import {
  bootstrapNdsGhidraProject,
  readNdsGhidraStatus,
} from "../services/nds/ghidra-project.js";
import type { NdsProcessor } from "../services/nds/overlays.js";

export interface NdsGhidraToolDependencies {
  readonly bootstrap: (romPath: string, config: ServerConfig) => Promise<unknown>;
  readonly status: (romPath: string, config: ServerConfig) => Promise<unknown>;
  readonly inspectFunction: (
    romPath: string,
    input: { readonly processor: NdsProcessor; readonly runtimeAddress: number; readonly overlayId?: number },
    config: ServerConfig,
  ) => Promise<unknown>;
  readonly decompileFunction: (
    romPath: string,
    input: {
      readonly processor: NdsProcessor;
      readonly runtimeAddress: number;
      readonly overlayId?: number;
      readonly maxCharacters?: number;
    },
    config: ServerConfig,
  ) => Promise<unknown>;
  readonly searchSymbols: (
    romPath: string,
    input: {
      readonly processor: NdsProcessor;
      readonly query: string;
      readonly match?: "exact" | "prefix" | "contains";
      readonly limit?: number;
      readonly offset?: number;
    },
    config: ServerConfig,
  ) => Promise<unknown>;
  readonly listReferences: (
    romPath: string,
    input: {
      readonly processor: NdsProcessor;
      readonly runtimeAddress: number;
      readonly overlayId?: number;
      readonly direction?: "from" | "to" | "both";
      readonly limit?: number;
      readonly offset?: number;
    },
    config: ServerConfig,
  ) => Promise<unknown>;
  readonly listCalls: (
    romPath: string,
    input: {
      readonly processor: NdsProcessor;
      readonly runtimeAddress: number;
      readonly overlayId?: number;
      readonly direction?: "callers" | "callees" | "both";
      readonly limit?: number;
      readonly offset?: number;
    },
    config: ServerConfig,
  ) => Promise<unknown>;
}

const DEFAULT_DEPENDENCIES: NdsGhidraToolDependencies = {
  bootstrap: bootstrapNdsGhidraProject,
  status: readNdsGhidraStatus,
  inspectFunction: inspectNdsGhidraFunction,
  decompileFunction: decompileNdsGhidraFunction,
  searchSymbols: searchNdsGhidraSymbols,
  listReferences: listNdsGhidraReferences,
  listCalls: listNdsGhidraCalls,
};

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
    case "ghidra-not-configured":
      return "Set RE_MCP_GHIDRA_HOME to a supported local Ghidra 12.x installation and restart RE-MCP.";
    case "invalid-ghidra-installation":
      return "Point RE_MCP_GHIDRA_HOME at a complete local Ghidra 12.x installation containing executable support/analyzeHeadless and the standard ARM language definitions.";
    case "unsupported-ghidra-version":
      return "Use a supported Ghidra 12.x installation; the reference acceptance release is Ghidra 12.1.2.";
    case "ghidra-language-unavailable":
      return "Use a Ghidra installation containing the exact ARM:LE:32:v5t and ARM:LE:32:v4t language definitions required for NDS ARM9 and ARM7.";
    case "ghidra-project-locked":
      return "Close the SHA-scoped project in other Ghidra GUI/headless processes, then retry without deleting or replacing the project.";
    case "bridge-generation-failed":
      return "Inspect the canonical NDS analysis bundle and generated bridge artifacts; RE-MCP will not invoke Ghidra with an invalid or tampered bridge.";
    case "ghidra-import-failed":
      return "Inspect the bounded Ghidra import diagnostics and installation compatibility; RE-MCP will not overwrite the SHA-scoped project to recover automatically.";
    case "ghidra-analysis-failed":
      return "Inspect the bounded Ghidra analysis diagnostics and generated processor result; the prior usable project is preserved.";
    case "ghidra-analysis-timeout":
      return "Increase RE_MCP_GHIDRA_TIMEOUT_MS within the 3600000 ms maximum or narrow external system load, then retry the SHA-scoped bootstrap.";
    case "ghidra-project-not-current":
      return "Run nds_ghidra_bootstrap for this unchanged ROM, then retry inspection only after it reports a complete current SHA-scoped project.";
    case "ghidra-version-mismatch":
      return "Use the same validated Ghidra version recorded by the current SHA-scoped project, or run nds_ghidra_bootstrap explicitly before inspection.";
    case "ghidra-address-not-inspectable":
      return "Choose one canonical main or uncompressed-overlay address and specify overlayId when static overlay ownership overlaps; compressed-overlay inspection requires controlled decompression first.";
    case "ghidra-inspection-failed":
      return "Inspect the bounded read-only Ghidra diagnostics. Inspection does not auto-bootstrap, auto-analyze, or modify the project.";
    case "ghidra-inspection-timeout":
      return "Retry after reducing external load or adjust RE_MCP_GHIDRA_TIMEOUT_MS within its bound; inspection still runs with auto-analysis disabled.";
    case "ghidra-inspection-result-invalid":
      return "Inspect the RE-MCP/Ghidra installation and generated inspection diagnostics; do not trust or reuse the invalid inspection result.";
    case "ghidra-output-limit":
      return "Increase RE_MCP_MAX_OUTPUT_BYTES to a safe bounded value or inspect why Ghidra is emitting excessive diagnostics before retrying.";
    case "project-state-mismatch":
      return "Inspect the SHA-scoped RE-MCP ownership state and Ghidra project. RE-MCP will not overwrite or destructively repair unrecognized analyst state.";
    case "invalid-rom":
      return "Use a readable Nintendo DS ROM path inside RE_MCP_WORKSPACE_ROOT and retry only after the source ROM is stable.";
    case "output-bound-exceeded":
      return "Increase RE_MCP_MAX_OUTPUT_BYTES or reduce the serialized result size so the bounded MCP response can be returned safely.";
    default:
      return "Inspect the NDS ROM, generated bridge, and Ghidra configuration; RE-MCP will not guess through an unresolved Ghidra integration failure.";
  }
}

function outputBoundResult(operation: string) {
  return textResult({
    error: "Serialized NDS Ghidra result exceeds RE_MCP_MAX_OUTPUT_BYTES",
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

function ghidraErrorResult(
  config: ServerConfig,
  operation: string,
  error: unknown,
) {
  const category = error instanceof NdsError
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

const romSchema = { rom: z.string().min(1) };
const processorSchema = z.enum(["arm9", "arm7"]);
const uint32Schema = z.number().int().min(0).max(0xffffffff);
const addressSchema = {
  ...romSchema,
  processor: processorSchema,
  runtimeAddress: uint32Schema,
  overlayId: uint32Schema.optional(),
};
const pageSchema = {
  limit: z.number().int().min(1).max(1000).optional(),
  offset: z.number().int().min(0).max(100000).optional(),
};

export function registerNdsGhidraTools(
  server: McpServer,
  config: ServerConfig,
  dependencies: NdsGhidraToolDependencies = DEFAULT_DEPENDENCIES,
): void {
  server.tool(
    "nds_ghidra_bootstrap",
    "Create or safely reconcile one full-SHA-scoped Ghidra project for a canonical Nintendo DS ROM using only the configured analyzeHeadless installation and RE-MCP-owned scripts.",
    romSchema,
    async ({ rom }) => {
      const operation = "nds_ghidra_bootstrap";
      try {
        const romPath = resolveInside(config.workspaceRoot, rom);
        const result = await dependencies.bootstrap(romPath, config);
        return boundedTextResult(config, operation, result);
      } catch (error) {
        return ghidraErrorResult(config, operation, error);
      }
    },
  );

  server.tool(
    "nds_ghidra_status",
    "Read the deterministic SHA-scoped Ghidra bridge/project state for a canonical Nintendo DS ROM without invoking Ghidra or mutating files.",
    romSchema,
    async ({ rom }) => {
      const operation = "nds_ghidra_status";
      try {
        const romPath = resolveInside(config.workspaceRoot, rom);
        const result = await dependencies.status(romPath, config);
        return boundedTextResult(config, operation, result);
      } catch (error) {
        return ghidraErrorResult(config, operation, error);
      }
    },
  );

  server.tool(
    "nds_ghidra_inspect_function",
    "Read Ghidra-derived function metadata at one canonical NDS runtime address from an already-current SHA-scoped project. Runs read-only with auto-analysis disabled.",
    addressSchema,
    async ({ rom, processor, runtimeAddress, overlayId }) => {
      const operation = "nds_ghidra_inspect_function";
      try {
        const romPath = resolveInside(config.workspaceRoot, rom);
        const result = await dependencies.inspectFunction(
          romPath,
          { processor, runtimeAddress, ...(overlayId === undefined ? {} : { overlayId }) },
          config,
        );
        return boundedTextResult(config, operation, result);
      } catch (error) {
        return ghidraErrorResult(config, operation, error);
      }
    },
  );

  server.tool(
    "nds_ghidra_decompile_function",
    "Return bounded Ghidra-derived C-like decompiler output for one canonical NDS function from an already-current project. Runs read-only with auto-analysis disabled.",
    {
      ...addressSchema,
      maxCharacters: z.number().int().min(1).max(100000).optional(),
    },
    async ({ rom, processor, runtimeAddress, overlayId, maxCharacters }) => {
      const operation = "nds_ghidra_decompile_function";
      try {
        const romPath = resolveInside(config.workspaceRoot, rom);
        const result = await dependencies.decompileFunction(
          romPath,
          {
            processor,
            runtimeAddress,
            ...(overlayId === undefined ? {} : { overlayId }),
            ...(maxCharacters === undefined ? {} : { maxCharacters }),
          },
          config,
        );
        return boundedTextResult(config, operation, result);
      } catch (error) {
        return ghidraErrorResult(config, operation, error);
      }
    },
  );

  server.tool(
    "nds_ghidra_search_symbols",
    "Search Ghidra/analyst symbols in one canonical ARM9 or ARM7 program using bounded exact, prefix, or contains matching. No regex or arbitrary query language is accepted.",
    {
      ...romSchema,
      processor: processorSchema,
      query: z.string().min(1).max(128),
      match: z.enum(["exact", "prefix", "contains"]).optional(),
      ...pageSchema,
    },
    async ({ rom, processor, query, match, limit, offset }) => {
      const operation = "nds_ghidra_search_symbols";
      try {
        const romPath = resolveInside(config.workspaceRoot, rom);
        const result = await dependencies.searchSymbols(
          romPath,
          {
            processor,
            query,
            ...(match === undefined ? {} : { match }),
            ...(limit === undefined ? {} : { limit }),
            ...(offset === undefined ? {} : { offset }),
          },
          config,
        );
        return boundedTextResult(config, operation, result);
      } catch (error) {
        return ghidraErrorResult(config, operation, error);
      }
    },
  );

  server.tool(
    "nds_ghidra_list_references",
    "List bounded Ghidra-derived references to/from one canonical NDS address in an already-current project. Ghidra references remain non-authoritative to RE-MCP.",
    {
      ...addressSchema,
      direction: z.enum(["from", "to", "both"]).optional(),
      ...pageSchema,
    },
    async ({ rom, processor, runtimeAddress, overlayId, direction, limit, offset }) => {
      const operation = "nds_ghidra_list_references";
      try {
        const romPath = resolveInside(config.workspaceRoot, rom);
        const result = await dependencies.listReferences(
          romPath,
          {
            processor,
            runtimeAddress,
            ...(overlayId === undefined ? {} : { overlayId }),
            ...(direction === undefined ? {} : { direction }),
            ...(limit === undefined ? {} : { limit }),
            ...(offset === undefined ? {} : { offset }),
          },
          config,
        );
        return boundedTextResult(config, operation, result);
      } catch (error) {
        return ghidraErrorResult(config, operation, error);
      }
    },
  );

  server.tool(
    "nds_ghidra_list_calls",
    "List bounded depth-one Ghidra-derived callers/callees for one canonical NDS function in an already-current project. No recursive graph traversal is exposed.",
    {
      ...addressSchema,
      direction: z.enum(["callers", "callees", "both"]).optional(),
      ...pageSchema,
    },
    async ({ rom, processor, runtimeAddress, overlayId, direction, limit, offset }) => {
      const operation = "nds_ghidra_list_calls";
      try {
        const romPath = resolveInside(config.workspaceRoot, rom);
        const result = await dependencies.listCalls(
          romPath,
          {
            processor,
            runtimeAddress,
            ...(overlayId === undefined ? {} : { overlayId }),
            ...(direction === undefined ? {} : { direction }),
            ...(limit === undefined ? {} : { limit }),
            ...(offset === undefined ? {} : { offset }),
          },
          config,
        );
        return boundedTextResult(config, operation, result);
      } catch (error) {
        return ghidraErrorResult(config, operation, error);
      }
    },
  );
}
