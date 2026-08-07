import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

import type { ServerConfig } from "../src/config.js";
import { registerNdsPatternTools } from "../src/tools/nds-pattern.js";
import { registerNdsTools } from "../src/tools/nds.js";
import { createNdsFixture } from "./helpers/nds-fixture.js";

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

  schema(name: string): z.ZodRawShape {
    return this.require(name).schema;
  }

  private require(name: string): RegisteredTool {
    const tool = this.tools.get(name);
    if (tool === undefined) throw new Error(`Unknown test tool: ${name}`);
    return tool;
  }
}

interface TextToolResult {
  readonly content: Array<{ readonly type: string; readonly text: string }>;
  readonly isError?: boolean;
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
  const mcp = server as unknown as McpServer;
  registerNdsTools(mcp, config(workspaceRoot, maxOutputBytes));
  registerNdsPatternTools(mcp, config(workspaceRoot, maxOutputBytes));
  return server;
}

function resultBody(result: unknown): Record<string, unknown> {
  const typed = result as TextToolResult;
  assert.equal(typed.content[0]?.type, "text");
  return JSON.parse(typed.content[0]!.text) as Record<string, unknown>;
}

function resultIsError(result: unknown): boolean {
  return (result as TextToolResult).isError === true;
}

test("registers exactly twelve combined NDS static-analysis tools", () => {
  const server = register("/workspace");
  assert.equal(server.tools.size, 12);
  assert.equal(server.tools.has("nds_search_pattern"), true);
});

test("pattern tool schema exposes exact defaults and bounded typed inputs", () => {
  const server = register("/workspace");
  assert.deepEqual(server.parse("nds_search_pattern", {
    rom: "game.nds",
    pattern: { kind: "byte-signature", signature: "AA ?? BB" },
    scope: { kind: "whole-rom" },
  }), {
    rom: "game.nds",
    pattern: { kind: "byte-signature", signature: "AA ?? BB" },
    scope: { kind: "whole-rom" },
    offset: 0,
    limit: 100,
    maxScanBytes: 64 * 1024 * 1024,
    contextBytes: 0,
  });

  assert.deepEqual(server.parse("nds_search_pattern", {
    rom: "game.nds",
    pattern: {
      kind: "integer",
      value: 0x1234,
      width: 16,
      endian: "little",
      signed: false,
      alignment: 2,
    },
    scope: {
      kind: "components",
      arm9Main: true,
      arm9OverlayIds: [7],
      nitroFsPaths: ["data.bin"],
    },
  }).pattern, {
    kind: "integer",
    value: 0x1234,
    width: 16,
    endian: "little",
    signed: false,
    alignment: 2,
  });

  for (const input of [
    { limit: 1001 },
    { offset: 100000 },
    { maxScanBytes: 512 * 1024 * 1024 + 1 },
    { contextBytes: 65 },
  ] as const) {
    assert.throws(() => server.parse("nds_search_pattern", {
      rom: "game.nds",
      pattern: { kind: "byte-signature", signature: "AA" },
      scope: { kind: "whole-rom" },
      ...input,
    }));
  }

  assert.throws(() => server.parse("nds_search_pattern", {
    rom: "game.nds",
    pattern: {
      kind: "integer",
      value: 1,
      width: 32,
      endian: "little",
      signed: false,
      alignment: 3,
    },
    scope: { kind: "whole-rom" },
  }));
});

test("pattern tool exposes no generic binary, arbitrary range, runtime, or output-path surface", () => {
  const server = register("/workspace");
  for (const forbidden of [
    "binary",
    "bytes",
    "baseAddress",
    "runtimeAddress",
    "start",
    "end",
    "length",
    "output",
    "path",
  ]) {
    assert.equal(Object.hasOwn(server.schema("nds_search_pattern"), forbidden), false);
  }
});

test("pattern tool returns bounded canonical search results", async () => {
  const fixture = await createNdsFixture({ arm9Size: 0x20 });
  fixture.buffer.set([0xaa, 0xaa, 0xaa], 0x200);
  await fixture.write();
  const server = register(fixture.directory);

  const result = await server.invoke("nds_search_pattern", {
    rom: path.basename(fixture.romPath),
    pattern: { kind: "byte-signature", signature: "AA AA" },
    scope: { kind: "components", arm9Main: true },
    limit: 10,
  });
  assert.equal(resultIsError(result), false);
  const body = resultBody(result);
  assert.equal(body.status, "complete");
  assert.match(String(body.sha256), /^[a-f0-9]{64}$/u);
  const matches = body.matches as Array<Record<string, unknown>>;
  assert.deepEqual(matches.map((hit) => hit.romOffset), [0x200, 0x201]);
});

test("pattern tool returns corrective actions for pattern and scope errors", async () => {
  const fixture = await createNdsFixture();
  const server = register(fixture.directory);
  const rom = path.basename(fixture.romPath);

  const malformed = await server.invoke("nds_search_pattern", {
    rom,
    pattern: { kind: "byte-signature", signature: "?? ??" },
    scope: { kind: "whole-rom" },
  });
  assert.equal(resultIsError(malformed), true);
  const malformedBody = resultBody(malformed);
  assert.equal(malformedBody.category, "invalid-pattern");
  assert.equal(typeof malformedBody.correctiveAction, "string");

  const emptyScope = await server.invoke("nds_search_pattern", {
    rom,
    pattern: { kind: "byte-signature", signature: "AA" },
    scope: { kind: "components" },
  });
  assert.equal(resultIsError(emptyScope), true);
  const scopeBody = resultBody(emptyScope);
  assert.equal(scopeBody.category, "invalid-pattern-scope");
  assert.equal(typeof scopeBody.correctiveAction, "string");
});

test("pattern tool reuses repository-wide serialized output ceiling", async () => {
  const fixture = await createNdsFixture({ arm9Size: 0x20 });
  fixture.buffer.fill(0xaa, 0x200, 0x220);
  await fixture.write();
  const server = register(fixture.directory, 256);

  const result = await server.invoke("nds_search_pattern", {
    rom: path.basename(fixture.romPath),
    pattern: { kind: "byte-signature", signature: "AA" },
    scope: { kind: "components", arm9Main: true },
    limit: 32,
    contextBytes: 4,
  });
  assert.equal(resultIsError(result), true);
  assert.equal(resultBody(result).category, "output-bound-exceeded");
});
