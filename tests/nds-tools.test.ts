import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

import type { ServerConfig } from "../src/config.js";
import { registerNdsTools } from "../src/tools/nds.js";
import {
  createNdsFixture,
  encodeFntFileEntry,
  writeFatEntry,
  writeFntMainRecord,
  writeFntSubtable,
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

  schema(name: string): z.ZodRawShape {
    return this.require(name).schema;
  }

  private require(name: string): RegisteredTool {
    const tool = this.tools.get(name);
    if (tool === undefined) throw new Error(`Unknown test tool: ${name}`);
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
  registerNdsTools(
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

async function buildToolRom() {
  const fixture = await createNdsFixture({
    fileSize: 0x5000,
    fntSize: 0x40,
    fatSize: 16,
    arm9OverlaySize: 32,
  });
  writeFatEntry(fixture.buffer, 0x900, 0, 0x1200, 0x1220);
  writeFatEntry(fixture.buffer, 0x900, 1, 0x1300, 0x1380);
  writeFntMainRecord(fixture.buffer, 0x800, 0, 8, 0, 1);
  writeFntSubtable(fixture.buffer, 0x800, 8, [encodeFntFileEntry("asset.bin")]);
  writeOverlayRecord(fixture.buffer, 0xa00, 0, {
    overlayId: 7,
    ramAddress: 0x02200000,
    ramSize: 0x100,
    bssSize: 0x20,
    staticInitStart: 0,
    staticInitEnd: 0,
    fileId: 1,
    compressedSize: 0x70,
    flags: 1,
  });
  fixture.buffer.fill(0xcc, 0x1200, 0x1220);
  fixture.buffer.fill(0xdd, 0x1300, 0x1380);
  await fixture.write();
  return { fixture, rom: path.basename(fixture.romPath) };
}

const EXPECTED_TOOLS = [
  "nds_inspect_rom",
  "nds_list_files",
  "nds_list_overlays",
  "nds_resolve_runtime_address",
  "nds_resolve_rom_offset",
  "nds_extract_component",
  "nds_extract_analysis_bundle",
] as const;

test("registers exactly the seven approved NDS static-analysis tools", () => {
  const server = register("/workspace");
  assert.deepEqual([...server.tools.keys()].sort(), [...EXPECTED_TOOLS].sort());
});

test("list and resolver schemas enforce approved defaults and bounds", () => {
  const server = register("/workspace");
  assert.deepEqual(server.parse("nds_list_files", { rom: "game.nds" }), {
    rom: "game.nds",
    prefix: "",
    limit: 100,
    offset: 0,
  });
  assert.deepEqual(server.parse("nds_list_overlays", { rom: "game.nds" }), {
    rom: "game.nds",
    processor: "all",
    limit: 100,
    offset: 0,
  });
  assert.throws(
    () => server.parse("nds_list_files", { rom: "game.nds", limit: 201 }),
    /less than or equal to 200/,
  );
  assert.throws(
    () => server.parse("nds_list_files", { rom: "game.nds", offset: -1 }),
    /greater than or equal to 0/,
  );
  assert.throws(
    () => server.parse("nds_resolve_runtime_address", {
      rom: "game.nds",
      processor: "arm9",
      address: 0x1_0000_0000,
    }),
    /less than or equal to 4294967295/,
  );
  assert.throws(
    () => server.parse("nds_resolve_rom_offset", { rom: "game.nds", offset: -1 }),
    /greater than or equal to 0/,
  );
});

test("component schema exposes no caller-controlled output path", () => {
  const server = register("/workspace");
  assert.equal(Object.hasOwn(server.schema("nds_extract_component"), "output"), false);
});

test("inspection and list tools expose bounded canonical ROM structure", async () => {
  const { fixture, rom } = await buildToolRom();
  const server = register(fixture.directory);

  const inspect = resultBody(await server.invoke("nds_inspect_rom", { rom }));
  assert.match(String(inspect.sha256), /^[a-f0-9]{64}$/);
  assert.equal(inspect.nitroFsFileCount, 2);
  assert.equal(inspect.arm9OverlayCount, 1);

  const files = resultBody(await server.invoke("nds_list_files", {
    rom,
    prefix: "asset",
    limit: 1,
  }));
  assert.equal(files.total, 1);
  assert.equal(files.offset, 0);
  assert.equal(files.limit, 1);
  assert.equal(files.nextOffset, null);
  const listedFiles = files.files as Array<Record<string, unknown>>;
  assert.equal(listedFiles[0]?.fileId, 0);
  assert.equal(listedFiles[0]?.path, "asset.bin");
  assert.equal(listedFiles[0]?.romOffset, 0x1200);

  const overlays = resultBody(await server.invoke("nds_list_overlays", {
    rom,
    processor: "arm9",
  }));
  assert.equal(overlays.total, 1);
  const listedOverlays = overlays.overlays as Array<Record<string, unknown>>;
  assert.equal(listedOverlays[0]?.overlayId, 7);
  assert.equal(listedOverlays[0]?.compressed, true);
});

test("resolver tools keep ambiguity/BSS/compression outcomes as successful structured results", async () => {
  const { fixture, rom } = await buildToolRom();
  const server = register(fixture.directory);
  const result = await server.invoke("nds_resolve_runtime_address", {
    rom,
    processor: "arm9",
    address: 0x02200020,
  });
  assert.equal(resultIsError(result), false);
  assert.equal(resultBody(result).status, "compressed-no-direct-rom-mapping");

  const romResult = await server.invoke("nds_resolve_rom_offset", {
    rom,
    offset: 0x1320,
  });
  assert.equal(resultIsError(romResult), false);
  const matches = resultBody(romResult).matches as Array<Record<string, unknown>>;
  assert.equal(matches.some((match) => match.kind === "arm9-overlay"), true);
});

test("workspace escapes return structured invalid-rom errors", async () => {
  const { fixture } = await buildToolRom();
  const server = register(fixture.directory);
  const result = await server.invoke("nds_inspect_rom", { rom: "../outside.nds" });
  assert.equal(resultIsError(result), true);
  const body = resultBody(result);
  assert.equal(body.operation, "nds_inspect_rom");
  assert.equal(body.category, "invalid-rom");
  assert.equal(typeof body.correctiveAction, "string");
});

test("output ceiling converts oversized results into output-bound-exceeded", async () => {
  const { fixture, rom } = await buildToolRom();
  const server = register(fixture.directory, 200);
  const result = await server.invoke("nds_inspect_rom", { rom });
  assert.equal(resultIsError(result), true);
  assert.equal(resultBody(result).category, "output-bound-exceeded");
});

test("component selector validation is strict and controlled extraction works", async () => {
  const { fixture, rom } = await buildToolRom();
  const server = register(fixture.directory);

  const invalid = await server.invoke("nds_extract_component", {
    rom,
    component: "arm9",
    overlayId: 7,
  });
  assert.equal(resultIsError(invalid), true);
  assert.equal(resultBody(invalid).category, "generated-path-failure");

  const duplicateFileSelector = await server.invoke("nds_extract_component", {
    rom,
    component: "nitrofs-file",
    fileId: 0,
    filePath: "asset.bin",
  });
  assert.equal(resultIsError(duplicateFileSelector), true);

  const extracted = resultBody(await server.invoke("nds_extract_component", {
    rom,
    component: "nitrofs-file",
    fileId: 0,
  }));
  assert.equal(extracted.fileId, 0);
  const output = String(extracted.output);
  assert.equal(output.startsWith(path.join(fixture.directory, "analysis", "generated", "nds")), true);
  assert.equal((await readFile(output)).equals(Buffer.alloc(0x20, 0xcc)), true);
});

test("analysis bundle tool returns controlled deterministic paths", async () => {
  const { fixture, rom } = await buildToolRom();
  const server = register(fixture.directory);
  const body = resultBody(await server.invoke("nds_extract_analysis_bundle", { rom }));
  assert.equal(String(body.outputRoot).startsWith(path.join(fixture.directory, "analysis", "generated", "nds")), true);
  await readFile(String(body.manifestPath));
});

test("index capability declaration includes all seven NDS tool names", async () => {
  const source = await readFile(path.resolve("src/index.ts"), "utf8");
  for (const name of EXPECTED_TOOLS) {
    assert.equal(source.includes(`\"${name}\"`), true, name);
  }
});
