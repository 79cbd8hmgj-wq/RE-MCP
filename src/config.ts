import path from "node:path";

export interface ServerConfig {
  readonly workspaceRoot: string;
  readonly commandTimeoutMs: number;
  readonly maxOutputBytes: number;
}

const DEFAULT_TIMEOUT_MS = 120_000;
const DEFAULT_MAX_OUTPUT_BYTES = 1_000_000;

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
  };
}
