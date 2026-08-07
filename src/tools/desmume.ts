import { constants as fsConstants } from "node:fs";
import { access } from "node:fs/promises";
import path from "node:path";

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

import type { ServerConfig } from "../config.js";
import { resolveInside } from "../security/paths.js";
import { DebugController } from "../services/debug-controller.js";
import type { ExecutableRangeInput } from "../services/executable-ranges.js";
import { GdbSession } from "../services/gdb-session.js";
import { validateMemoryRead } from "../services/gdb-rsp.js";
import { readArm9ExecutableRange } from "../services/nds-arm9.js";
import {
  OwnedProcessManager,
  type OwnedProcessStatus,
} from "../services/owned-process.js";
import { probeTcpPort, waitForTcpPort } from "../services/tcp-probe.js";
import { buildDesmumeArguments, validateGdbPort } from "./desmume-policy.js";

const uint32Schema = z.number().int().min(0).max(0xffffffff);
const safeIdentifierSchema = z.string().regex(/^[A-Za-z0-9._-]{1,64}$/);
const breakpointModeSchema = z.enum(["arm", "thumb", "auto"]);
const resolvedModeSchema = z.enum(["arm", "thumb"]);
const stopContextRegionSchema = z.object({
  label: safeIdentifierSchema,
  address: uint32Schema,
  length: z.number().int().min(1).max(4096),
});
const executableRangeSchema = z.object({
  id: safeIdentifierSchema,
  label: z.string().min(1).max(128),
  start: uint32Schema,
  end: uint32Schema,
  source: z.enum(["overlay", "explicit"]),
  overlayId: z.number().int().min(0).optional(),
  defaultMode: resolvedModeSchema.optional(),
  symbolModes: z.record(resolvedModeSchema).optional(),
});

function textResult(value: unknown, isError = false) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(value, null, 2) }],
    isError,
  };
}

function ownedGdbPort(manager: OwnedProcessManager): number {
  const status = manager.status();
  if (!status.running) {
    throw new Error("No owned DeSmuME process is running");
  }
  const port = status.metadata.arm9GdbPort;
  if (typeof port !== "number") {
    throw new Error("Owned DeSmuME session does not expose an ARM9 GDB port");
  }
  return validateGdbPort(port);
}

function ownedProcessIdentity(status: OwnedProcessStatus): string {
  if (!status.running || status.pid === null || status.startedAt === null) {
    throw new Error("Owned DeSmuME process does not expose a stable running identity");
  }
  return `desmume:${status.pid}:${status.startedAt}`;
}

function debuggerCorrectiveAction(
  status: OwnedProcessStatus,
  controller: DebugController,
  message: string,
): string {
  if (!status.running) {
    return "Start DeSmuME with desmume_start before using debugger tools.";
  }
  if (/not initialized/i.test(message)) {
    return "Restart the owned DeSmuME session with desmume_start so debugger metadata is initialized.";
  }
  if (controller.state() === "unavailable") {
    return "Use desmume_wait_for_gdb to confirm the owned ARM9 GDB stub is reachable, then retry.";
  }
  if (controller.state() === "running") {
    return "Use desmume_wait_for_stop or desmume_pause before an operation that requires stopped state.";
  }
  return "Inspect the debugger state and retry only after the reported condition is corrected.";
}

function debuggerErrorResult(
  operation: string,
  error: unknown,
  manager: OwnedProcessManager,
  controller: DebugController,
) {
  const message = error instanceof Error ? error.message : String(error);
  const status = manager.status();
  const state = controller.state();
  return textResult(
    {
      error: message,
      operation,
      debuggerState: state,
      emulatorRunning: status.running,
      connectionUsable: status.running && state !== "unavailable",
      correctiveAction: debuggerCorrectiveAction(status, controller, message),
    },
    true,
  );
}

function normalizeExecutableRanges(
  ranges: readonly z.infer<typeof executableRangeSchema>[],
): readonly ExecutableRangeInput[] {
  return ranges.map((range) => ({
    id: range.id,
    label: range.label,
    start: range.start,
    end: range.end,
    source: range.source,
    ...(range.overlayId === undefined ? {} : { overlayId: range.overlayId }),
    ...(range.defaultMode === undefined ? {} : { defaultMode: range.defaultMode }),
    ...(range.symbolModes === undefined ? {} : { symbolModes: range.symbolModes }),
  }));
}

export function createDesmumeDebugController(
  config: ServerConfig,
  manager: OwnedProcessManager,
): DebugController {
  return new DebugController(() =>
    new GdbSession({
      host: "127.0.0.1",
      port: ownedGdbPort(manager),
      maxReplyBytes: Math.max(8_256, config.maxOutputBytes),
      connectTimeoutMs: Math.min(5_000, config.commandTimeoutMs),
    }),
  );
}

export function registerDesmumeTools(
  server: McpServer,
  config: ServerConfig,
  manager: OwnedProcessManager,
  debuggerController: DebugController = createDesmumeDebugController(config, manager),
): DebugController {
  server.tool(
    "desmume_status",
    "Report the single DeSmuME process owned by this RE-MCP server instance.",
    {},
    async () => textResult(manager.status()),
  );

  server.tool(
    "desmume_start",
    "Start the verified DeSmuME debug launcher with one local ROM and ARM9 GDB port.",
    {
      launcher: z.string().min(1),
      rom: z.string().min(1),
      arm9GdbPort: z.number().int().default(20000),
    },
    async ({ launcher, rom, arm9GdbPort }) => {
      try {
        const launcherPath = resolveInside(config.workspaceRoot, launcher);
        const romPath = resolveInside(config.workspaceRoot, rom);
        const port = validateGdbPort(arm9GdbPort);
        await access(launcherPath, fsConstants.X_OK);
        await access(romPath, fsConstants.R_OK);
        const arm9Range = await readArm9ExecutableRange(romPath);

        const status = await manager.start({
          executable: launcherPath,
          args: buildDesmumeArguments(port, romPath),
          cwd: path.dirname(launcherPath),
          maxOutputBytes: config.maxOutputBytes,
          metadata: { emulator: "desmume", arm9GdbPort: port, rom: romPath },
        });
        const sessionIdentity = ownedProcessIdentity(status);
        debuggerController.initialize(sessionIdentity, arm9Range);
        return textResult({
          ...status,
          debugger: {
            sessionIdentity,
            state: debuggerController.state(),
            arm9ExecutableRange: arm9Range,
          },
        });
      } catch (error) {
        return textResult({ error: error instanceof Error ? error.message : String(error) }, true);
      }
    },
  );

  server.tool("desmume_probe_gdb", "Probe the owned localhost ARM9 GDB port.", {}, async () => {
    try {
      const port = ownedGdbPort(manager);
      if (debuggerController.state() !== "unavailable") {
        return textResult({
          host: "127.0.0.1",
          port,
          reachable: true,
          elapsedMs: 0,
          error: null,
          source: "persistent-debugger-session",
        });
      }
      const result = await probeTcpPort("127.0.0.1", port, 1_000);
      return textResult(result, !result.reachable);
    } catch (error) {
      return textResult({ error: error instanceof Error ? error.message : String(error) }, true);
    }
  });

  server.tool(
    "desmume_wait_for_gdb",
    "Wait a bounded interval for the owned ARM9 GDB port.",
    { timeoutMs: z.number().int().min(100).max(30_000).default(10_000) },
    async ({ timeoutMs }) => {
      try {
        const port = ownedGdbPort(manager);
        if (debuggerController.state() !== "unavailable") {
          return textResult({
            host: "127.0.0.1",
            port,
            reachable: true,
            elapsedMs: 0,
            error: null,
            source: "persistent-debugger-session",
          });
        }
        const result = await waitForTcpPort("127.0.0.1", port, timeoutMs);
        return textResult(result, !result.reachable);
      } catch (error) {
        return textResult({ error: error instanceof Error ? error.message : String(error) }, true);
      }
    },
  );

  server.tool("desmume_read_register_packet", "Read the raw ARM9 GDB register packet.", {}, async () => {
    try {
      ownedGdbPort(manager);
      const payload = await debuggerController.readRegisterPacket(3_000);
      return textResult({ registerHex: payload, byteLength: payload.length / 2 });
    } catch (error) {
      return textResult({ error: error instanceof Error ? error.message : String(error) }, true);
    }
  });

  server.tool(
    "desmume_read_memory",
    "Read at most 4096 bytes from ARM9 memory through GDB RSP.",
    {
      address: uint32Schema,
      length: z.number().int().min(1).max(4096),
    },
    async ({ address, length }) => {
      try {
        ownedGdbPort(manager);
        validateMemoryRead(address, length);
        const payload = await debuggerController.readMemory(address, length, 3_000);
        return textResult({ address, length, dataHex: payload });
      } catch (error) {
        return textResult({ error: error instanceof Error ? error.message : String(error) }, true);
      }
    },
  );

  server.tool(
    "desmume_breakpoint_add",
    "Install one bounded ARM9 software breakpoint inside an allowlisted executable range.",
    {
      address: uint32Schema,
      mode: breakpointModeSchema,
      symbol: z.string().min(1).max(128).optional(),
      rangeId: safeIdentifierSchema.optional(),
    },
    async ({ address, mode, symbol, rangeId }) => {
      try {
        ownedGdbPort(manager);
        const breakpoint = await debuggerController.addBreakpoint({
          address,
          mode,
          timeoutMs: 3_000,
          ...(symbol === undefined ? {} : { symbol }),
          ...(rangeId === undefined ? {} : { rangeId }),
        });
        return textResult(breakpoint);
      } catch (error) {
        return debuggerErrorResult("desmume_breakpoint_add", error, manager, debuggerController);
      }
    },
  );

  server.tool(
    "desmume_breakpoint_remove",
    "Remove one breakpoint previously installed by this debugger session.",
    { id: z.string().regex(/^bp-[1-9][0-9]*$/) },
    async ({ id }) => {
      try {
        ownedGdbPort(manager);
        return textResult(await debuggerController.removeBreakpoint(id, 3_000));
      } catch (error) {
        return debuggerErrorResult("desmume_breakpoint_remove", error, manager, debuggerController);
      }
    },
  );

  server.tool(
    "desmume_breakpoint_list",
    "List session-scoped breakpoints and their hit counts.",
    {},
    async () => {
      try {
        ownedGdbPort(manager);
        return textResult({
          debuggerState: debuggerController.state(),
          maximum: debuggerController.maximumBreakpoints(),
          breakpoints: debuggerController.listBreakpoints(),
        });
      } catch (error) {
        return debuggerErrorResult("desmume_breakpoint_list", error, manager, debuggerController);
      }
    },
  );

  server.tool(
    "desmume_continue",
    "Continue ARM9 execution for a bounded interval and return the first observed stop or timeout.",
    {
      timeoutMs: z.number().int().min(100).max(30_000).default(10_000),
      captureContext: z.boolean().default(true),
      expectedBreakpointId: z.string().regex(/^bp-[1-9][0-9]*$/).optional(),
      additionalRegions: z.array(stopContextRegionSchema).max(8).optional(),
    },
    async ({ timeoutMs, captureContext, expectedBreakpointId, additionalRegions }) => {
      try {
        ownedGdbPort(manager);
        return textResult(await debuggerController.continueExecution({
          timeoutMs,
          captureContext,
          maxOutputBytes: config.maxOutputBytes,
          ...(expectedBreakpointId === undefined ? {} : { expectedBreakpointId }),
          ...(additionalRegions === undefined ? {} : { additionalRegions }),
        }));
      } catch (error) {
        return debuggerErrorResult("desmume_continue", error, manager, debuggerController);
      }
    },
  );

  server.tool(
    "desmume_step_instruction",
    "Single-step from 1 through 100 ARM9 instructions with a bounded wait per step.",
    {
      count: z.number().int().min(1).max(100),
      perStepTimeoutMs: z.number().int().min(100).max(5_000).default(1_000),
      captureContext: z.boolean().default(true),
      additionalRegions: z.array(stopContextRegionSchema).max(8).optional(),
    },
    async ({ count, perStepTimeoutMs, captureContext, additionalRegions }) => {
      try {
        ownedGdbPort(manager);
        return textResult(await debuggerController.step({
          count,
          perStepTimeoutMs,
          captureContext,
          maxOutputBytes: config.maxOutputBytes,
          ...(additionalRegions === undefined ? {} : { additionalRegions }),
        }));
      } catch (error) {
        return debuggerErrorResult("desmume_step_instruction", error, manager, debuggerController);
      }
    },
  );

  server.tool(
    "desmume_pause",
    "Interrupt a running ARM9 target and wait a bounded interval for its stop reply.",
    {
      timeoutMs: z.number().int().min(100).max(5_000).default(1_000),
      captureContext: z.boolean().default(true),
      additionalRegions: z.array(stopContextRegionSchema).max(8).optional(),
    },
    async ({ timeoutMs, captureContext, additionalRegions }) => {
      try {
        ownedGdbPort(manager);
        return textResult(await debuggerController.pause({
          timeoutMs,
          captureContext,
          maxOutputBytes: config.maxOutputBytes,
          ...(additionalRegions === undefined ? {} : { additionalRegions }),
        }));
      } catch (error) {
        return debuggerErrorResult("desmume_pause", error, manager, debuggerController);
      }
    },
  );

  server.tool(
    "desmume_wait_for_stop",
    "Wait for a currently running ARM9 target to stop without issuing a new continue command.",
    {
      timeoutMs: z.number().int().min(100).max(30_000),
      captureContext: z.boolean().default(true),
      additionalRegions: z.array(stopContextRegionSchema).max(8).optional(),
    },
    async ({ timeoutMs, captureContext, additionalRegions }) => {
      try {
        ownedGdbPort(manager);
        return textResult(await debuggerController.waitForStop({
          timeoutMs,
          captureContext,
          maxOutputBytes: config.maxOutputBytes,
          ...(additionalRegions === undefined ? {} : { additionalRegions }),
        }));
      } catch (error) {
        return debuggerErrorResult("desmume_wait_for_stop", error, manager, debuggerController);
      }
    },
  );

  server.tool(
    "desmume_capture_stop_context",
    "Capture decoded ARM9 registers and bounded memory around the current stopped PC and SP.",
    {
      timeoutMs: z.number().int().min(100).max(5_000).default(1_000),
      additionalRegions: z.array(stopContextRegionSchema).max(8).optional(),
    },
    async ({ timeoutMs, additionalRegions }) => {
      try {
        ownedGdbPort(manager);
        return textResult(await debuggerController.captureCurrentStopContext({
          timeoutMs,
          maxOutputBytes: config.maxOutputBytes,
          ...(additionalRegions === undefined ? {} : { additionalRegions }),
        }));
      } catch (error) {
        return debuggerErrorResult("desmume_capture_stop_context", error, manager, debuggerController);
      }
    },
  );

  server.tool(
    "desmume_executable_ranges_replace",
    "Replace the session-scoped additional ARM9 executable-range allowlist.",
    { ranges: z.array(executableRangeSchema).max(64) },
    async ({ ranges }) => {
      try {
        ownedGdbPort(manager);
        debuggerController.replaceAdditionalRanges(normalizeExecutableRanges(ranges));
        return textResult({ ranges: debuggerController.listExecutableRanges() });
      } catch (error) {
        return debuggerErrorResult(
          "desmume_executable_ranges_replace",
          error,
          manager,
          debuggerController,
        );
      }
    },
  );

  server.tool("desmume_stop", "Stop only the owned DeSmuME process.", {}, async () => {
    try {
      const status = await manager.stop();
      await debuggerController.reset("Owned DeSmuME process stopped");
      return textResult(status);
    } catch (error) {
      return textResult({ error: error instanceof Error ? error.message : String(error) }, true);
    }
  });

  return debuggerController;
}
