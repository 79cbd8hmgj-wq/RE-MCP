import path from "node:path";

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

import type { ServerConfig } from "../config.js";
import type { DebugController } from "../services/debug-controller.js";
import { createCapstoneArmBackend } from "../services/disassembly/capstone.js";
import {
  NdsError,
  type NdsRuntimeCorrelationErrorCategory,
} from "../services/nds/errors.js";
import { correlateNdsStopContext } from "../services/nds/runtime-correlation.js";
import type { OwnedProcessManager, OwnedProcessStatus } from "../services/owned-process.js";

const SHA256_PATTERN = /^[0-9a-f]{64}$/u;

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

function requireOwnedRuntime(status: OwnedProcessStatus): {
  readonly romPath: string;
  readonly romSha256: string;
} {
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

  return { romPath, romSha256 };
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

function correctiveAction(category: NdsRuntimeCorrelationErrorCategory): string {
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
      return "Verify the owned debugger session and workspace ROM path, capture a valid stopped ARM9 context, and retry.";
    case "runtime-correlation-output-limit":
      return "Reduce nearbyInstructions or referenceLimit so the bounded correlation result fits RE_MCP_MAX_OUTPUT_BYTES.";
  }
}

function errorResult(
  operation: string,
  error: unknown,
  manager: OwnedProcessManager,
  debuggerController: DebugController,
) {
  const category: NdsRuntimeCorrelationErrorCategory = error instanceof NdsError
    && error.category.startsWith("runtime-correlation-")
    ? error.category as NdsRuntimeCorrelationErrorCategory
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
    "Correlate the current stopped server-owned DeSmuME ARM9 state with the exact launched NDS ROM and bounded canonical static evidence without resuming execution.",
    {
      timeoutMs: z.number().int().min(100).max(30_000).default(3_000),
      nearbyInstructions: z.number().int().min(1).max(32).default(8),
      referenceLimit: z.number().int().min(0).max(64).default(16),
    },
    async ({ timeoutMs, nearbyInstructions, referenceLimit }) => {
      const operation = "nds_correlate_stop_context";
      try {
        const { romPath, romSha256 } = requireOwnedRuntime(manager.status());
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

        const backend = await createCapstoneArmBackend();
        try {
          return textResult(await correlateNdsStopContext(
            {
              romPath,
              romDisplayPath,
              expectedRomSha256: romSha256,
              stopContext: context,
              options: {
                nearbyInstructions,
                referenceLimit,
                maxOutputBytes: config.maxOutputBytes,
                includeGhidra: false,
                decompileGhidraFunction: false,
              },
            },
            backend,
          ));
        } finally {
          backend.close();
        }
      } catch (error) {
        return errorResult(operation, error, manager, debuggerController);
      }
    },
  );
}
