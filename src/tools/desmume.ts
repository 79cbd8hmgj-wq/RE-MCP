import { constants as fsConstants } from "node:fs";
import { access } from "node:fs/promises";
import path from "node:path";

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

import type { ServerConfig } from "../config.js";
import { resolveInside } from "../security/paths.js";
import { OwnedProcessManager } from "../services/owned-process.js";
import { buildDesmumeArguments, validateGdbPort } from "./desmume-policy.js";

function textResult(value: unknown, isError = false) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(value, null, 2) }],
    isError,
  };
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

        const status = await manager.start({
          executable: launcherPath,
          args: buildDesmumeArguments(port, romPath),
          cwd: path.dirname(launcherPath),
          maxOutputBytes: config.maxOutputBytes,
          metadata: {
            emulator: "desmume",
            arm9GdbPort: port,
            rom: romPath,
          },
        });
        return textResult(status);
      } catch (error) {
        return textResult({ error: error instanceof Error ? error.message : String(error) }, true);
      }
    },
  );

  server.tool(
    "desmume_stop",
    "Stop only the DeSmuME process owned by this RE-MCP server instance.",
    {},
    async () => {
      try {
        return textResult(await manager.stop());
      } catch (error) {
        return textResult({ error: error instanceof Error ? error.message : String(error) }, true);
      }
    },
  );
}
