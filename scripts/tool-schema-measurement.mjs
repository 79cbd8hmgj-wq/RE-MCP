import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

export async function measureToolSchemas(profile, options = {}) {
  if (typeof profile !== "string" || profile.trim().length === 0) {
    throw new Error("Tool profile must be a non-empty string");
  }
  const packageRoot = path.resolve(options.packageRoot ?? ".");
  const workspace = await mkdtemp(path.join(os.tmpdir(), "re-mcp-schema-"));
  const client = new Client({ name: "re-mcp-schema-measure", version: "1.0.0" });
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [path.join(packageRoot, "dist", "index.js")],
    env: {
      ...Object.fromEntries(
        Object.entries(process.env).filter((entry) => entry[1] !== undefined),
      ),
      RE_MCP_WORKSPACE_ROOT: workspace,
      RE_MCP_TOOL_PROFILE: profile.trim(),
    },
    stderr: "pipe",
  });

  try {
    await client.connect(transport);
    const result = await client.listTools();
    const serialized = JSON.stringify(result.tools);
    const serializedBytes = Buffer.byteLength(serialized, "utf8");
    return {
      profile: profile.trim(),
      toolCount: result.tools.length,
      serializedBytes,
      estimatedTokens: Math.ceil(serializedBytes / 4),
    };
  } finally {
    await client.close().catch(() => undefined);
    await rm(workspace, { recursive: true, force: true });
  }
}
