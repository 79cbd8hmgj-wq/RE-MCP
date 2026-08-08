import assert from "node:assert/strict";
import test from "node:test";

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

import type { ServerConfig } from "../src/config.js";
import { NdsError } from "../src/services/nds/errors.js";
import {
  registerNdsGhidraTools,
  type NdsGhidraToolDependencies,
} from "../src/tools/nds-ghidra.js";

interface RegisteredTool {
  readonly schema: z.ZodRawShape;
  readonly handler: (input: Record<string, unknown>) => Promise<unknown>;
}

class FakeMcpServer {
  readonly tools = new Map<string, RegisteredTool>();
  tool(name: string, _description: string, schema: z.ZodRawShape, handler: RegisteredTool["handler"]): void {
    this.tools.set(name, { schema, handler });
  }
  parse(name: string, input: unknown): Record<string, unknown> {
    return z.object(this.tools.get(name)!.schema).parse(input);
  }
  async invoke(name: string, input: unknown): Promise<unknown> {
    const tool = this.tools.get(name)!;
    return tool.handler(this.parse(name, input));
  }
}

function config(maxOutputBytes = 64 * 1024): ServerConfig {
  return {
    workspaceRoot: "/workspace",
    commandTimeoutMs: 30_000,
    maxOutputBytes,
    ghidraHome: "/opt/ghidra_12.1.2_PUBLIC",
    ghidraTimeoutMs: 900_000,
  };
}

function dependencies(): NdsGhidraToolDependencies {
  const success = async (romPath: string, input?: unknown) => ({ romPath, input, ok: true });
  return {
    bootstrap: success,
    status: success,
    inspectFunction: success,
    decompileFunction: success,
    searchSymbols: success,
    listReferences: success,
    listCalls: success,
  } as unknown as NdsGhidraToolDependencies;
}

function register(cfg = config(), deps = dependencies()): FakeMcpServer {
  const server = new FakeMcpServer();
  registerNdsGhidraTools(server as unknown as McpServer, cfg, deps);
  return server;
}

interface TextResult {
  readonly content: Array<{ readonly type: string; readonly text: string }>;
  readonly isError?: boolean;
}

function body(result: unknown): Record<string, unknown> {
  return JSON.parse((result as TextResult).content[0]!.text) as Record<string, unknown>;
}

test("registers exactly seven controlled NDS Ghidra tools", () => {
  const server = register();
  assert.deepEqual([...server.tools.keys()].sort(), [
    "nds_ghidra_bootstrap",
    "nds_ghidra_decompile_function",
    "nds_ghidra_inspect_function",
    "nds_ghidra_list_calls",
    "nds_ghidra_list_references",
    "nds_ghidra_search_symbols",
    "nds_ghidra_status",
  ]);
});

test("Ghidra inspection schemas expose canonical selectors and bounded controls only", () => {
  const server = register();
  const addressTools = [
    "nds_ghidra_inspect_function",
    "nds_ghidra_decompile_function",
    "nds_ghidra_list_references",
    "nds_ghidra_list_calls",
  ];
  for (const name of addressTools) {
    const parsed = server.parse(name, {
      rom: "game.nds",
      processor: "arm9",
      runtimeAddress: 0x02000000,
      overlayId: 7,
    });
    assert.equal(parsed.processor, "arm9");
    assert.equal(parsed.runtimeAddress, 0x02000000);
    assert.equal(parsed.overlayId, 7);
  }

  assert.deepEqual(server.parse("nds_ghidra_search_symbols", {
    rom: "game.nds",
    processor: "arm7",
    query: "FUN_",
    match: "contains",
    limit: 1000,
    offset: 100000,
  }), {
    rom: "game.nds",
    processor: "arm7",
    query: "FUN_",
    match: "contains",
    limit: 1000,
    offset: 100000,
  });

  assert.throws(() => server.parse("nds_ghidra_decompile_function", {
    rom: "game.nds", processor: "arm9", runtimeAddress: 0x02000000, maxCharacters: 100001,
  }));
  assert.throws(() => server.parse("nds_ghidra_search_symbols", {
    rom: "game.nds", processor: "arm9", query: "", limit: 1,
  }));
  assert.throws(() => server.parse("nds_ghidra_list_references", {
    rom: "game.nds", processor: "arm9", runtimeAddress: 0x02000000, limit: 1001,
  }));
  assert.throws(() => server.parse("nds_ghidra_list_calls", {
    rom: "game.nds", processor: "arm9", runtimeAddress: -1,
  }));

  const forbidden = [
    "executable", "projectPath", "programName", "addressSpace", "scriptPath",
    "args", "env", "outputPath", "ensureCurrent", "bootstrap",
  ];
  for (const name of addressTools.concat("nds_ghidra_search_symbols")) {
    const schema = server.tools.get(name)!.schema;
    for (const key of forbidden) assert.equal(key in schema, false, `${name}:${key}`);
  }
});

test("Ghidra inspection tools route workspace-contained ROMs and bounded inputs", async () => {
  const server = register();
  const inspected = body(await server.invoke("nds_ghidra_inspect_function", {
    rom: "roms/game.nds",
    processor: "arm9",
    runtimeAddress: 0x02000000,
  }));
  assert.equal(inspected.romPath, "/workspace/roms/game.nds");

  const symbols = body(await server.invoke("nds_ghidra_search_symbols", {
    rom: "game.nds",
    processor: "arm7",
    query: "FUN_",
  }));
  assert.equal(symbols.romPath, "/workspace/game.nds");
});

test("Ghidra inspection errors preserve dedicated categories and corrective actions", async () => {
  const failing = dependencies() as unknown as Record<string, unknown>;
  failing.inspectFunction = async () => {
    throw new NdsError("ghidra-project-not-current", "project stale");
  };
  const server = register(config(), failing as unknown as NdsGhidraToolDependencies);
  const result = await server.invoke("nds_ghidra_inspect_function", {
    rom: "game.nds", processor: "arm9", runtimeAddress: 0x02000000,
  }) as TextResult;
  assert.equal(result.isError, true);
  const parsed = body(result);
  assert.equal(parsed.category, "ghidra-project-not-current");
  assert.match(String(parsed.correctiveAction), /nds_ghidra_bootstrap/i);
});
