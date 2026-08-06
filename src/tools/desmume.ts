import { constants as fsConstants } from "node:fs";
import { access } from "node:fs/promises";
import path from "node:path";

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

import type { ServerConfig } from "../config.js";
import { resolveInside } from "../security/paths.js";
import { sendRspCommand, validateMemoryRead } from "../services/gdb-rsp.js";
import { OwnedProcessManager } from "../services/owned-process.js";
import { probeTcpPort, waitForTcpPort } from "../services/tcp-probe.js";
import {
  buildDesmumeArguments,
  type DesmumeLauncherMode,
  validateGdbPort,
} from "./desmume-policy.js";

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

export function registerDesmumeTools(
  server: McpServer,
  config: ServerConfig,
  manager: OwnedProcessManager,
): void {
  server.tool(
    "desmume_status",
    "Report the single DeSmuME process owned by this RE-MCP server instance.",
    {},
    async () => textResult(manager.status()),
  );

  server.tool(
    "desmume_start",
    "Start the verified Linux CLI or macOS Cocoa DeSmuME launcher with one local ROM.",
    {
      launcher: z.string().min(1),
      rom: z.string().min(1),
      mode: z.enum(["linux-cli", "macos-cocoa"]).default("linux-cli"),
      arm9GdbPort: z.number().int().default(20000),
    },
    async ({ launcher, rom, mode, arm9GdbPort }) => {
      try {
        const launcherPath = resolveInside(config.workspaceRoot, launcher);
        const romPath = resolveInside(config.workspaceRoot, rom);
        const port = validateGdbPort(arm9GdbPort);
        await access(launcherPath, fsConstants.X_OK);
        await access(romPath, fsConstants.R_OK);

        const launcherMode = mode as DesmumeLauncherMode;
        const status = await manager.start({
          executable: launcherPath,
          args: buildDesmumeArguments(launcherMode, port, romPath),
          cwd: path.dirname(launcherPath),
          maxOutputBytes: config.maxOutputBytes,
          metadata: {
            emulator: "desmume",
            launcherMode,
            arm9GdbPort: port,
            rom: romPath,
            gdbStartup:
              launcherMode === "macos-cocoa"
                ? "Start ARM9 from Tools > Show GDB Stub Control"
                : "automatic",
          },
        });
        return textResult(status);
      } catch (error) {
        return textResult({ error: error instanceof Error ? error.message : String(error) }, true);
      }
    },
  );

  server.tool("desmume_probe_gdb", "Probe the owned localhost ARM9 GDB port.", {}, async () => {
    try {
      const result = await probeTcpPort("127.0.0.1", ownedGdbPort(manager), 1_000);
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
        const result = await waitForTcpPort("127.0.0.1", ownedGdbPort(manager), timeoutMs);
        return textResult(result, !result.reachable);
      } catch (error) {
        return textResult({ error: error instanceof Error ? error.message : String(error) }, true);
      }
    },
  );

  server.tool("desmume_read_register_packet", "Read the raw ARM9 GDB register packet.", {}, async () => {
    try {
      const reply = await sendRspCommand(
        "127.0.0.1",
        ownedGdbPort(manager),
        "g",
        3_000,
        config.maxOutputBytes,
      );
      return textResult({ registerHex: reply.payload, byteLength: reply.payload.length / 2 });
    } catch (error) {
      return textResult({ error: error instanceof Error ? error.message : String(error) }, true);
    }
  });

  server.tool(
    "desmume_read_memory",
    "Read at most 4096 bytes from ARM9 memory through GDB RSP.",
    {
      address: z.number().int().min(0).max(0xffffffff),
      length: z.number().int().min(1).max(4096),
    },
    async ({ address, length }) => {
      try {
        validateMemoryRead(address, length);
        const command = `m${address.toString(16)},${length.toString(16)}`;
        const reply = await sendRspCommand(
          "127.0.0.1",
          ownedGdbPort(manager),
          command,
          3_000,
          Math.min(config.maxOutputBytes, length * 2 + 64),
        );
        if (reply.payload.startsWith("E")) {
          throw new Error(`GDB memory read failed: ${reply.payload}`);
        }
        return textResult({ address, length, dataHex: reply.payload });
      } catch (error) {
        return textResult({ error: error instanceof Error ? error.message : String(error) }, true);
      }
    },
  );

  server.tool("desmume_stop", "Stop only the owned DeSmuME process.", {}, async () => {
    try {
      return textResult(await manager.stop());
    } catch (error) {
      return textResult({ error: error instanceof Error ? error.message : String(error) }, true);
    }
  });
}
