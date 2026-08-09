import assert from "node:assert/strict";
import test from "node:test";

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

import type { ServerConfig } from "../src/config.js";
import { registerNdsMutationTools } from "../src/tools/nds-mutation.js";

interface RegisteredTool {
  readonly schema: z.ZodRawShape;
  readonly handler: (input: Record<string, unknown>) => Promise<unknown>;
}

class FakeMcpServer {
  readonly tools = new Map<string, RegisteredTool>();

  tool(
    name: string,
    _description: string,
    schema: z.ZodRawShape,
    handler: (input: Record<string, unknown>) => Promise<unknown>,
  ): void {
    this.tools.set(name, { schema, handler });
  }

  parse(name: string, input: unknown): Record<string, unknown> {
    const tool = this.tools.get(name);
    if (tool === undefined) throw new Error(`Unknown test tool: ${name}`);
    return z.object(tool.schema).strict().parse(input);
  }
}

function config(): ServerConfig {
  return {
    workspaceRoot: "/workspace",
    commandTimeoutMs: 30_000,
    maxOutputBytes: 64 * 1024,
  };
}

test("registers exactly the three controlled NDS mutation tools", () => {
  const server = new FakeMcpServer();
  registerNdsMutationTools(server as unknown as McpServer, config());
  assert.deepEqual([...server.tools.keys()].sort(), [
    "nds_mutation_build",
    "nds_mutation_validate",
    "nds_mutation_verify",
  ]);
});

test("mutation tool schemas accept only ROM and manifest paths", () => {
  const server = new FakeMcpServer();
  registerNdsMutationTools(server as unknown as McpServer, config());

  for (const name of [
    "nds_mutation_validate",
    "nds_mutation_build",
    "nds_mutation_verify",
  ]) {
    assert.deepEqual(server.parse(name, {
      rom: "roms/game.nds",
      manifest: "plans/mod.json",
    }), {
      rom: "roms/game.nds",
      manifest: "plans/mod.json",
    });
    assert.throws(() => server.parse(name, {
      rom: "roms/game.nds",
      manifest: "plans/mod.json",
      output: "/tmp/game.nds",
    }));
  }
});
