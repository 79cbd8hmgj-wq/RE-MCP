import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

import type { ServerConfig } from "../config.js";
import { resolveInside } from "../security/paths.js";
import { NdsError } from "../services/nds/errors.js";
import {
  bootstrapNdsGhidraProject,
  readNdsGhidraStatus,
} from "../services/nds/ghidra-project.js";

export interface NdsGhidraToolDependencies {
  readonly bootstrap: (romPath: string, config: ServerConfig) => Promise<unknown>;
  readonly status: (romPath: string, config: ServerConfig) => Promise<unknown>;
}

const DEFAULT_DEPENDENCIES: NdsGhidraToolDependencies = {
  bootstrap: bootstrapNdsGhidraProject,
  status: readNdsGhidraStatus,
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

export function registerNdsGhidraTools(
  server: McpServer,
  config: ServerConfig,
  dependencies: NdsGhidraToolDependencies = DEFAULT_DEPENDENCIES,
): void {
  const schema = { rom: z.string().min(1) };

  server.tool(
    "nds_ghidra_bootstrap",
    "Create or safely reconcile one full-SHA-scoped Ghidra project for a canonical Nintendo DS ROM using only the configured analyzeHeadless installation and RE-MCP-owned scripts.",
    schema,
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
    schema,
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
}
