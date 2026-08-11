import path from "node:path";

import {
  isToolProfileName,
  TOOL_PROFILE_NAMES,
  type ToolProfileName,
} from "./tools/profiles.js";

export interface ServerConfig {
  readonly workspaceRoot: string;
  readonly commandTimeoutMs: number;
  readonly maxOutputBytes: number;
  readonly ghidraHome?: string | null;
  readonly ghidraTimeoutMs?: number;
  readonly toolProfile: ToolProfileName;
}

const DEFAULT_TIMEOUT_MS = 120_000;
const DEFAULT_MAX_OUTPUT_BYTES = 1_000_000;
const DEFAULT_GHIDRA_TIMEOUT_MS = 900_000;
const MAX_GHIDRA_TIMEOUT_MS = 3_600_000;
const DEFAULT_TOOL_PROFILE: ToolProfileName = "re-full";

function positiveInteger(value: string | undefined, fallback: number, name: string): number {
  if (value === undefined || value.length === 0) {
    return fallback;
  }

  const parsed = Number.parseInt(value, 10);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new Error(`${name} must be a positive integer`);
  }
  return parsed;
}

function boundedPositiveInteger(
  value: string | undefined,
  fallback: number,
  maximum: number,
  name: string,
): number {
  const parsed = positiveInteger(value, fallback, name);
  if (parsed > maximum) {
    throw new Error(`${name} must be between 1 and ${maximum}`);
  }
  return parsed;
}

function toolProfile(value: string | undefined): ToolProfileName {
  const normalized = value?.trim() || DEFAULT_TOOL_PROFILE;
  if (!isToolProfileName(normalized)) {
    throw new Error(
      `RE_MCP_TOOL_PROFILE must be one of: ${TOOL_PROFILE_NAMES.join(", ")}`,
    );
  }
  return normalized;
}

export function loadConfig(environment: NodeJS.ProcessEnv = process.env): ServerConfig {
  const configuredRoot = environment.RE_MCP_WORKSPACE_ROOT;
  if (configuredRoot === undefined || configuredRoot.trim().length === 0) {
    throw new Error("RE_MCP_WORKSPACE_ROOT is required");
  }

  return {
    workspaceRoot: path.resolve(configuredRoot),
    commandTimeoutMs: positiveInteger(
      environment.RE_MCP_COMMAND_TIMEOUT_MS,
      DEFAULT_TIMEOUT_MS,
      "RE_MCP_COMMAND_TIMEOUT_MS",
    ),
    maxOutputBytes: positiveInteger(
      environment.RE_MCP_MAX_OUTPUT_BYTES,
      DEFAULT_MAX_OUTPUT_BYTES,
      "RE_MCP_MAX_OUTPUT_BYTES",
    ),
    ghidraHome: environment.RE_MCP_GHIDRA_HOME?.trim()
      ? path.resolve(environment.RE_MCP_GHIDRA_HOME)
      : null,
    ghidraTimeoutMs: boundedPositiveInteger(
      environment.RE_MCP_GHIDRA_TIMEOUT_MS,
      DEFAULT_GHIDRA_TIMEOUT_MS,
      MAX_GHIDRA_TIMEOUT_MS,
      "RE_MCP_GHIDRA_TIMEOUT_MS",
    ),
    toolProfile: toolProfile(environment.RE_MCP_TOOL_PROFILE),
  };
}
