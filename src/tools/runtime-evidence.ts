import path from "node:path";

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

import type { ServerConfig } from "../config.js";
import { resolveInside } from "../security/paths.js";
import {
  captureRuntimeEvidence,
  writeEvidenceAtomic,
} from "../services/runtime-evidence.js";
import { OwnedProcessManager } from "../services/owned-process.js";
import { assertGeneratedAnalysisPath } from "./bakugan-policy.js";
import { validateGdbPort } from "./desmume-policy.js";

const BAKUGAN_PROJECT = "Bakugan-DS-";

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

export function registerRuntimeEvidenceTools(
  server: McpServer,
  config: ServerConfig,
  manager: OwnedProcessManager,
): void {
  server.tool(
    "desmume_capture_runtime_evidence",
    "Atomically save raw ARM9 registers and bounded memory regions without interpreting them.",
    {
      project: z.string().default(BAKUGAN_PROJECT),
      output: z.string().default("analysis/generated/runtime-evidence.json"),
      regions: z
        .array(
          z.object({
            label: z.string().min(1).max(64),
            address: z.number().int().min(0).max(0xffffffff),
            length: z.number().int().min(1).max(4096),
          }),
        )
        .max(16)
        .default([]),
    },
    async ({ project, output, regions }) => {
      try {
        const projectRoot = resolveInside(config.workspaceRoot, project);
        const outputPath = assertGeneratedAnalysisPath(projectRoot, output);
        const evidence = await captureRuntimeEvidence(
          ownedGdbPort(manager),
          regions,
          config.maxOutputBytes,
        );
        await writeEvidenceAtomic(outputPath, evidence);
        return textResult({
          output: outputPath,
          capturedAt: evidence.capturedAt,
          registerBytes: evidence.registerHex.length / 2,
          memoryRegionCount: evidence.memoryRegions.length,
          memoryBytes: evidence.memoryRegions.reduce(
            (total, region) => total + region.length,
            0,
          ),
        });
      } catch (error) {
        return textResult(
          { error: error instanceof Error ? error.message : String(error) },
          true,
        );
      }
    },
  );
}
