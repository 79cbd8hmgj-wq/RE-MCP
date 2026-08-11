#!/usr/bin/env node

import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const profile = process.argv[2] ?? "re-static-core";
const workspace = await mkdtemp(path.join(os.tmpdir(), "re-mcp-schema-"));
const client = new Client({ name: "re-mcp-schema-measure", version: "1.0.0" });
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [path.resolve("dist/index.js")],
  env: {
    ...process.env,
    RE_MCP_WORKSPACE_ROOT: workspace,
    RE_MCP_TOOL_PROFILE: profile,
  },
  stderr: "pipe",
});

try {
  await client.connect(transport);
  const result = await client.listTools();
  const serialized = JSON.stringify(result.tools);
  const serializedBytes = Buffer.byteLength(serialized, "utf8");
  process.stdout.write(`${JSON.stringify({
    profile,
    toolCount: result.tools.length,
    serializedBytes,
    estimatedTokens: Math.ceil(serializedBytes / 4),
  }, null, 2)}\n`);
} finally {
  await client.close().catch(() => undefined);
  await rm(workspace, { recursive: true, force: true });
}
