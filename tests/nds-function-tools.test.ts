import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

import type { ServerConfig } from "../src/config.js";
import { registerNdsFunctionTools } from "../src/tools/nds-functions.js";
import {
  createNdsFixture,
  writeFatEntry,
  writeOverlayRecord,
} from "./helpers/nds-fixture.js";

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
    const tool = this.require(name);
    return z.object(tool.schema).parse(input);
  }

  async invoke(name: string, input: unknown): Promise<unknown> {
    const tool = this.require(name);
    return await tool.handler(this.parse(name, input));
  }

  private require(name: string): RegisteredTool {
    const tool = this.tools.get(name);
    if (tool === undefined) {
      throw new Error(`Unknown test tool: ${name}`);
    }
    return tool;
  }
}

function config(workspaceRoot: string, maxOutputBytes = 64 * 1024): ServerConfig {
  return {
    workspaceRoot,
    commandTimeoutMs: 30_000,
    maxOutputBytes,
  };
}

function register(workspaceRoot: string, maxOutputBytes = 64 * 1024): FakeMcpServer {
  const server = new FakeMcpServer();
  registerNdsFunctionTools(
    server as unknown as McpServer,
    config(workspaceRoot, maxOutputBytes),
  );
  return server;
}

interface TextToolResult {
  readonly content: Array<{ readonly type: string; readonly text: string }>;
  readonly isError?: boolean;
}

function resultBody(result: unknown): Record<string, unknown> {
  const typed = result as TextToolResult;
  assert.equal(typed.content[0]?.type, "text");
  return JSON.parse(typed.content[0]!.text) as Record<string, unknown>;
}

function resultIsError(result: unknown): boolean {
  return (result as TextToolResult).isError === true;
}

async function buildFunctionToolRom() {
  const fixture = await createNdsFixture({ arm9Size: 0x20 });
  fixture.buffer.set([0x1e, 0xff, 0x2f, 0xe1], 0x200); // bx lr
  await fixture.write();
  return { fixture, rom: path.basename(fixture.romPath) };
}

async function buildAmbiguousOverlayRom() {
  const fixture = await createNdsFixture({
    fileSize: 0x5000,
    fatSize: 16,
    arm9OverlaySize: 64,
  });
  writeFatEntry(fixture.buffer, 0x900, 0, 0x1200, 0x1280);
  writeFatEntry(fixture.buffer, 0x900, 1, 0x1300, 0x1380);
  for (const [index, overlayId, fileId] of [[0, 7, 0], [1, 8, 1]] as const) {
    writeOverlayRecord(fixture.buffer, 0xa00, index, {
      overlayId,
      ramAddress: 0x02200000,
      ramSize: 0x80,
      bssSize: 0,
      staticInitStart: 0,
      staticInitEnd: 0,
      fileId,
      compressedSize: 0,
      flags: 0,
    });
  }
  await fixture.write();
  return { fixture, rom: path.basename(fixture.romPath) };
}

test("registers exactly the two NDS proven-function tools", () => {
  const server = register("/workspace");
  assert.deepEqual([...server.tools.keys()].sort(), [
    "nds_analyze_function",
    "nds_discover_functions",
  ]);
});

test("function discovery schema exposes approved defaults and maxima", () => {
  const server = register("/workspace");
  assert.deepEqual(server.parse("nds_discover_functions", {
    rom: "game.nds",
    processor: "arm9",
    scope: { kind: "main" },
  }), {
    rom: "game.nds",
    processor: "arm9",
    scope: { kind: "main" },
    seeds: [],
    maxComponents: 32,
    maxFunctions: 128,
    maxCallSites: 512,
    maxTotalBlocks: 512,
    maxTotalInstructions: 4096,
    maxTotalBytes: 32768,
    maxTotalEdges: 2048,
    maxCfgBlocksPerFunction: 64,
    maxCfgInstructionsPerFunction: 512,
    maxCfgBytesPerFunction: 2048,
    maxCfgEdgesPerFunction: 128,
  });

  assert.throws(
    () => server.parse("nds_discover_functions", {
      rom: "game.nds",
      processor: "arm9",
      scope: { kind: "main" },
      maxFunctions: 1025,
    }),
    /less than or equal to 1024/,
  );
  assert.throws(
    () => server.parse("nds_discover_functions", {
      rom: "game.nds",
      processor: "arm9",
      scope: { kind: "main" },
      maxCallSites: 8193,
    }),
    /less than or equal to 8192/,
  );
  assert.throws(
    () => server.parse("nds_discover_functions", {
      rom: "game.nds",
      processor: "arm9",
      scope: { kind: "main" },
      maxTotalInstructions: 32769,
    }),
    /less than or equal to 32768/,
  );
  assert.throws(
    () => server.parse("nds_discover_functions", {
      rom: "game.nds",
      processor: "arm9",
      scope: { kind: "main" },
      maxTotalBytes: 262145,
    }),
    /less than or equal to 262144/,
  );
  assert.throws(
    () => server.parse("nds_discover_functions", {
      rom: "game.nds",
      processor: "arm9",
      scope: { kind: "main" },
      maxTotalEdges: 16385,
    }),
    /less than or equal to 16384/,
  );
  assert.throws(
    () => server.parse("nds_discover_functions", {
      rom: "game.nds",
      processor: "arm9",
      scope: { kind: "main" },
      maxComponents: 0,
    }),
    /greater than or equal to 1/,
  );
});

test("focused function analysis schema exposes approved defaults and maxima", () => {
  const server = register("/workspace");
  assert.deepEqual(server.parse("nds_analyze_function", {
    rom: "game.nds",
    processor: "arm9",
    runtimeAddress: 0x02000000,
    mode: "arm",
    proofScope: { kind: "main" },
  }), {
    rom: "game.nds",
    processor: "arm9",
    runtimeAddress: 0x02000000,
    mode: "arm",
    proofScope: { kind: "main" },
    seeds: [],
    maxProofComponents: 32,
    maxProofBlocks: 128,
    maxProofInstructions: 2048,
    maxProofBytes: 8192,
    maxProofEdges: 512,
    maxProofCallSites: 256,
    maxCfgBlocks: 64,
    maxCfgInstructions: 512,
    maxCfgBytes: 2048,
    maxCfgEdges: 128,
  });

  for (const [field, value, maximum] of [
    ["maxProofComponents", 129, 128],
    ["maxProofBlocks", 513, 512],
    ["maxProofInstructions", 16385, 16384],
    ["maxProofBytes", 65537, 65536],
    ["maxProofEdges", 4097, 4096],
    ["maxProofCallSites", 2049, 2048],
    ["maxCfgBlocks", 257, 256],
    ["maxCfgInstructions", 4097, 4096],
    ["maxCfgBytes", 16385, 16384],
    ["maxCfgEdges", 1025, 1024],
  ] as const) {
    assert.throws(
      () => server.parse("nds_analyze_function", {
        rom: "game.nds",
        processor: "arm9",
        runtimeAddress: 0x02000000,
        mode: "arm",
        proofScope: { kind: "main" },
        [field]: value,
      }),
      new RegExp(`less than or equal to ${maximum}`),
    );
  }

  assert.throws(
    () => server.parse("nds_analyze_function", {
      rom: "game.nds",
      processor: "arm9",
      runtimeAddress: 0x02000000,
      mode: "arm",
      proofScope: { kind: "main" },
      maxProofBlocks: 0,
    }),
    /greater than or equal to 1/,
  );
});

test("function schemas bound seeds and use exact ARM Thumb modes", () => {
  const server = register("/workspace");
  const seeds = Array.from({ length: 129 }, (_, index) => ({
    runtimeAddress: 0x02000000 + index * 4,
    mode: "arm" as const,
  }));

  assert.throws(
    () => server.parse("nds_discover_functions", {
      rom: "game.nds",
      processor: "arm9",
      scope: { kind: "main" },
      seeds,
    }),
    /less than or equal to 128|at most 128/i,
  );
  assert.throws(
    () => server.parse("nds_analyze_function", {
      rom: "game.nds",
      processor: "arm9",
      runtimeAddress: 0x02000000,
      mode: "auto",
      proofScope: { kind: "main" },
    }),
  );
});

test("function tool reports function-specific scope corrective action", async () => {
  const { fixture, rom } = await buildFunctionToolRom();
  const server = register(fixture.directory);
  const result = await server.invoke("nds_discover_functions", {
    rom,
    processor: "arm9",
    scope: { kind: "main-and-overlays", overlayIds: [7, 7] },
  });

  assert.equal(resultIsError(result), true);
  const body = resultBody(result);
  assert.equal(body.category, "invalid-function-scope");
  assert.match(String(body.correctiveAction), /without duplicate overlay IDs/i);
});

test("focused function tool reports ambiguous requested entry without guessing", async () => {
  const { fixture, rom } = await buildAmbiguousOverlayRom();
  const server = register(fixture.directory);
  const result = await server.invoke("nds_analyze_function", {
    rom,
    processor: "arm9",
    runtimeAddress: 0x02200010,
    mode: "arm",
    proofScope: { kind: "main" },
  });

  assert.equal(resultIsError(result), true);
  const body = resultBody(result);
  assert.equal(body.category, "function-entry-not-uniquely-resolved");
  assert.match(String(body.correctiveAction), /one exact initialized executable source/i);
});

test("function tool applies the standard serialized output bound", async () => {
  const { fixture, rom } = await buildFunctionToolRom();
  const server = register(fixture.directory, 32);
  const result = await server.invoke("nds_discover_functions", {
    rom,
    processor: "arm9",
    scope: { kind: "main" },
  });

  assert.equal(resultIsError(result), true);
  const body = resultBody(result);
  assert.equal(body.category, "output-bound-exceeded");
  assert.equal(body.operation, "nds_discover_functions");
});
