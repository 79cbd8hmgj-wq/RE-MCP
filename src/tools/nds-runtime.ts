import path from "node:path";

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

import type { ServerConfig } from "../config.js";
import type { DebugController } from "../services/debug-controller.js";
import { DisassemblyBackendError } from "../services/disassembly/backend.js";
import { createCapstoneArmBackend } from "../services/disassembly/capstone.js";
import {
  NdsError,
  type NdsRuntimeCorrelationErrorCategory,
  type NdsServiceErrorCategory,
} from "../services/nds/errors.js";
import { createRuntimeGhidraEnricher } from "../services/nds/runtime-correlation-ghidra.js";
import { correlateNdsStopContext } from "../services/nds/runtime-correlation.js";
import type { OwnedProcessManager, OwnedProcessStatus } from "../services/owned-process.js";

const SHA256_PATTERN = /^[0-9a-f]{64}$/u;

type RuntimeToolErrorCategory = NdsServiceErrorCategory | "disassembly-backend-failure";

interface OwnedRuntimeIdentity {
  readonly romPath: string;
  readonly romSha256: string;
  readonly pid: number;
  readonly startedAt: string;
}

function textResult(value: unknown, isError = false) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(value, null, 2) }],
    isError,
  };
}

function correlationError(
  category: NdsRuntimeCorrelationErrorCategory,
  message: string,
): NdsError<NdsRuntimeCorrelationErrorCategory> {
  return new NdsError(category, message);
}

function requireOwnedRuntime(status: OwnedProcessStatus): OwnedRuntimeIdentity {
  if (!status.running) {
    throw correlationError(
      "runtime-correlation-no-owned-process",
      "No owned DeSmuME process is running",
    );
  }

  const romPath = status.metadata.rom;
  const romSha256 = status.metadata.romSha256;
  if (
    typeof romPath !== "string"
    || romPath.length === 0
    || typeof romSha256 !== "string"
    || !SHA256_PATTERN.test(romSha256)
  ) {
    throw correlationError(
      "runtime-correlation-rom-identity-missing",
      "Owned DeSmuME process lacks a valid launch-time ROM path/SHA-256 identity; restart it with desmume_start",
    );
  }
  if (status.pid === null || status.startedAt === null) {
    throw correlationError(
      "runtime-correlation-context-failed",
      "Owned DeSmuME process lacks a stable process-generation identity",
    );
  }

  return {
    romPath,
    romSha256,
    pid: status.pid,
    startedAt: status.startedAt,
  };
}

function sameOwnedRuntimeGeneration(
  expected: OwnedRuntimeIdentity,
  current: OwnedProcessStatus,
): boolean {
  return current.running
    && current.pid === expected.pid
    && current.startedAt === expected.startedAt
    && current.metadata.rom === expected.romPath
    && current.metadata.romSha256 === expected.romSha256;
}

function requireSameOwnedRuntimeGeneration(
  expected: OwnedRuntimeIdentity,
  current: OwnedProcessStatus,
): void {
  if (!sameOwnedRuntimeGeneration(expected, current)) {
    throw correlationError(
      "runtime-correlation-context-failed",
      "Owned DeSmuME process generation changed during runtime correlation",
    );
  }
}

function workspaceDisplayPath(config: ServerConfig, romPath: string): string {
  if (!path.isAbsolute(romPath)) {
    throw correlationError(
      "runtime-correlation-context-failed",
      "Owned ROM path is not an absolute server-controlled path",
    );
  }
  const displayPath = path.relative(config.workspaceRoot, romPath);
  if (
    path.isAbsolute(displayPath)
    || displayPath === ".."
    || displayPath.startsWith(`..${path.sep}`)
  ) {
    throw correlationError(
      "runtime-correlation-context-failed",
      "Owned ROM path is outside the configured workspace",
    );
  }
  return displayPath.split(path.sep).join("/");
}

function correctiveAction(category: RuntimeToolErrorCategory): string {
  switch (category) {
    case "runtime-correlation-no-owned-process":
      return "Start the intended ROM with desmume_start, then stop at the code of interest before correlating.";
    case "runtime-correlation-rom-identity-missing":
      return "Restart the owned emulator with the current desmume_start so its process generation receives a full launch-time ROM SHA-256.";
    case "runtime-correlation-rom-identity-mismatch":
      return "Stop DeSmuME and restart it with the unchanged ROM that should be correlated; live and static evidence must share one full SHA-256.";
    case "runtime-correlation-debugger-not-stopped":
      return "Use desmume_wait_for_stop or desmume_pause, then retry correlation while the shared ARM9 debugger is stopped.";
    case "runtime-correlation-context-failed":
      return "Verify the owned debugger session, correlation options, and workspace ROM path, capture a valid stopped ARM9 context, and retry.";
    case "runtime-correlation-output-limit":
      return "Reduce nearbyInstructions or referenceLimit so the bounded correlation result fits RE_MCP_MAX_OUTPUT_BYTES.";
    case "disassembly-backend-failure":
      return "Verify the packaged ARM/Thumb disassembly backend and retry the stopped-state correlation.";
    default:
      return "Resolve the reported canonical NDS/static-analysis validation error and retry; runtime correlation does not override lower-layer failures.";
  }
}

function errorResult(
  operation: string,
  error: unknown,
  manager: OwnedProcessManager,
  debuggerController: DebugController,
) {
  const category: RuntimeToolErrorCategory = error instanceof DisassemblyBackendError
    ? error.category
    : error instanceof NdsError
      ? error.category
      : "runtime-correlation-context-failed";
  const message = error instanceof Error ? error.message : String(error);
  return textResult({
    error: message,
    operation,
    category,
    debuggerState: debuggerController.status().state,
    emulatorRunning: manager.status().running,
    correctiveAction: correctiveAction(category),
  }, true);
}

export function registerNdsRuntimeTools(
  server: McpServer,
  config: ServerConfig,
  manager: OwnedProcessManager,
  debuggerController: DebugController,
): void {
  server.tool(
    "nds_correlate_stop_context",
    "Correlate the current stopped server-owned DeSmuME ARM9 state with the exact launched NDS ROM and bounded canonical static evidence, optionally enriching from an already-current read-only Ghidra project, without resuming execution.",
    {
      timeoutMs: z.number().int().min(100).max(30_000).default(3_000),
      nearbyInstructions: z.number().int().min(1).max(32).default(8),
      referenceLimit: z.number().int().min(0).max(64).default(16),
      includeGhidra: z.boolean().default(false),
      decompileGhidraFunction: z.boolean().default(false),
    },
    async ({
      timeoutMs,
      nearbyInstructions,
      referenceLimit,
      includeGhidra,
      decompileGhidraFunction,
    }) => {
      const operation = "nds_correlate_stop_context";
      try {
        if (decompileGhidraFunction && !includeGhidra) {
          throw correlationError(
            "runtime-correlation-context-failed",
            "decompileGhidraFunction requires includeGhidra",
          );
        }
        const runtimeIdentity = requireOwnedRuntime(manager.status());
        const { romPath, romSha256 } = runtimeIdentity;
        if (debuggerController.status().state !== "stopped") {
          throw correlationError(
            "runtime-correlation-debugger-not-stopped",
            `Runtime correlation requires stopped debugger state; current state is ${debuggerController.status().state}`,
          );
        }
        const romDisplayPath = workspaceDisplayPath(config, romPath);

        let context;
        try {
          context = await debuggerController.captureCurrentStopContext({
            timeoutMs,
            maxOutputBytes: config.maxOutputBytes,
          });
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error);
          throw correlationError(
            "runtime-correlation-context-failed",
            `Unable to capture the current stopped ARM9 context: ${message}`,
          );
        }
        requireSameOwnedRuntimeGeneration(runtimeIdentity, manager.status());

        const backend = await createCapstoneArmBackend();
        try {
          const ghidraEnricher = includeGhidra
            ? createRuntimeGhidraEnricher(config)
            : undefined;
          const result = await correlateNdsStopContext(
            {
              romPath,
              romDisplayPath,
              expectedRomSha256: romSha256,
              stopContext: context,
              options: {
                nearbyInstructions,
                referenceLimit,
                maxOutputBytes: config.maxOutputBytes,
                includeGhidra,
                decompileGhidraFunction,
              },
            },
            backend,
            ghidraEnricher,
          );
          requireSameOwnedRuntimeGeneration(runtimeIdentity, manager.status());
          return textResult(result);
        } finally {
          backend.close();
        }
      } catch (error) {
        return errorResult(operation, error, manager, debuggerController);
      }
    },
  );
}
