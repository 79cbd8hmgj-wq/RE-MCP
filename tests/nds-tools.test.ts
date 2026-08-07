import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

import type { ServerConfig } from "../src/config.js";
import { registerNdsPatternTools } from "../src/tools/nds-pattern.js";
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
  const mcp = server as unknown as McpServer;
  const serverConfig = config(workspaceRoot, maxOutputBytes);
  registerNdsTools(mcp, serverConfig);
  registerNdsPatternTools(mcp, serverConfig);
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

async function buildDisassemblyRom() {
  const fixture = await createNdsFixture();
  fixture.buffer.set([0x1e, 0xff, 0x2f, 0xe1], 0x200);
  await fixture.write();
  return { fixture, rom: path.basename(fixture.romPath) };
}

async function buildReferenceRom() {
  const fixture = await createNdsFixture({ arm9Size: 0x20 });
  fixture.buffer.set([0x00, 0x00, 0x00, 0xeb], 0x200);
  fixture.buffer.set([0x1e, 0xff, 0x2f, 0xe1], 0x204);
  fixture.buffer.set([0x1e, 0xff, 0x2f, 0xe1], 0x208);
  await fixture.write();
  return { fixture, rom: path.basename(fixture.romPath) };
}

async function buildPatternRom() {
  const fixture = await createNdsFixture({ arm9Size: 0x20 });
  fixture.buffer.set([0xaa, 0xaa, 0xaa], 0x200);
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
  "nds_disassemble_range",
  "nds_analyze_control_flow",
  "nds_list_references",
  "nds_find_xrefs",
  "nds_search_pattern",
] as const;

test("registers exactly the twelve approved NDS static-analysis tools", () => {
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

test("disassembly schemas expose exact defaults, caps, and no generic binary surface", () => {
  const server = register("/workspace");
  assert.deepEqual(server.parse("nds_disassemble_range", {
    rom: "game.nds",
    processor: "arm9",
    runtimeAddress: 0x02000000,
  }), {
    rom: "game.nds",
    processor: "arm9",
    runtimeAddress: 0x02000000,
    mode: "auto",
    maxInstructions: 32,
    maxBytes: 128,
  });
  assert.deepEqual(server.parse("nds_analyze_control_flow", {
    rom: "game.nds",
    processor: "arm9",
    runtimeAddress: 0x02000000,
  }), {
    rom: "game.nds",
    processor: "arm9",
    runtimeAddress: 0x02000000,
    mode: "auto",
    maxBlocks: 64,
    maxInstructions: 512,
    maxBytes: 2048,
    maxEdges: 128,
  });

  assert.throws(
    () => server.parse("nds_disassemble_range", {
      rom: "game.nds", processor: "arm9", runtimeAddress: 0x02000000,
      maxInstructions: 257,
    }),
    /less than or equal to 256/,
  );
  assert.throws(
    () => server.parse("nds_disassemble_range", {
      rom: "game.nds", processor: "arm9", runtimeAddress: 0x02000000,
      maxBytes: 1025,
    }),
    /less than or equal to 1024/,
  );
  for (const [field, value] of [
    ["maxBlocks", 257],
    ["maxInstructions", 4097],
    ["maxBytes", 16385],
    ["maxEdges", 1025],
  ] as const) {
    assert.throws(
      () => server.parse("nds_analyze_control_flow", {
        rom: "game.nds",
        processor: "arm9",
        runtimeAddress: 0x02000000,
        [field]: value,
      }),
      /less than or equal to/,
    );
  }

  for (const forbidden of [
    "binary",
    "bytes",
    "baseAddress",
    "output",
    "path",
    "length",
  ]) {
    assert.equal(
      Object.hasOwn(server.schema("nds_disassemble_range"), forbidden),
      false,
    );
    assert.equal(
      Object.hasOwn(server.schema("nds_analyze_control_flow"), forbidden),
      false,
    );
  }
});

test("reference schemas expose exact defaults, caps, scopes, seeds, and no generic binary surface", () => {
  const server = register("/workspace");
  assert.deepEqual(server.parse("nds_list_references", {
    rom: "game.nds",
    processor: "arm9",
    runtimeAddress: 0x02000000,
  }), {
    rom: "game.nds",
    processor: "arm9",
    runtimeAddress: 0x02000000,
    mode: "auto",
    maxInstructions: 32,
    maxBytes: 128,
  });
  assert.deepEqual(server.parse("nds_find_xrefs", {
    rom: "game.nds",
    processor: "arm9",
    targetRuntimeAddress: 0x02000008,
    scope: { kind: "main" },
  }), {
    rom: "game.nds",
    processor: "arm9",
    targetRuntimeAddress: 0x02000008,
    scope: { kind: "main" },
    seeds: [],
    maxComponents: 32,
    maxBlocks: 128,
    maxInstructions: 2048,
    maxBytes: 8192,
    maxEdges: 512,
    maxXrefs: 256,
  });
  assert.deepEqual(server.parse("nds_find_xrefs", {
    rom: "game.nds",
    processor: "arm9",
    targetRomOffset: 0x208,
    scope: { kind: "main-and-overlays", overlayIds: [7] },
    seeds: [{ runtimeAddress: 0x02200000, mode: "thumb", overlayId: 7 }],
  }).scope, { kind: "main-and-overlays", overlayIds: [7] });

  for (const [field, value] of [
    ["maxComponents", 129],
    ["maxBlocks", 513],
    ["maxInstructions", 16385],
    ["maxBytes", 65537],
    ["maxEdges", 4097],
    ["maxXrefs", 2049],
  ] as const) {
    assert.throws(
      () => server.parse("nds_find_xrefs", {
        rom: "game.nds",
        processor: "arm9",
        targetRuntimeAddress: 0x02000008,
        scope: { kind: "main" },
        [field]: value,
      }),
      /less than or equal to/,
    );
  }
  assert.throws(
    () => server.parse("nds_find_xrefs", {
      rom: "game.nds",
      processor: "arm9",
      targetRuntimeAddress: 0x02000008,
      scope: { kind: "overlay", overlayIds: [] },
    }),
  );
  assert.throws(
    () => server.parse("nds_find_xrefs", {
      rom: "game.nds",
      processor: "arm9",
      targetRuntimeAddress: 0x02000008,
      scope: { kind: "main-and-overlays", overlayIds: [] },
    }),
  );
  assert.throws(
    () => server.parse("nds_find_xrefs", {
      rom: "game.nds",
      processor: "arm9",
      targetRuntimeAddress: 0x02000008,
      scope: { kind: "overlay", overlayIds: Array.from({ length: 129 }, (_, index) => index) },
    }),
  );
  assert.throws(
    () => server.parse("nds_find_xrefs", {
      rom: "game.nds",
      processor: "arm9",
      targetRuntimeAddress: 0x02000008,
      scope: { kind: "main" },
      seeds: Array.from({ length: 513 }, () => ({ runtimeAddress: 0x02000000, mode: "arm" })),
    }),
  );

  for (const forbidden of [
    "binary",
    "bytes",
    "baseAddress",
    "output",
    "path",
    "length",
  ]) {
    assert.equal(Object.hasOwn(server.schema("nds_list_references"), forbidden), false);
    assert.equal(Object.hasOwn(server.schema("nds_find_xrefs"), forbidden), false);
  }
});

test("pattern search schema exposes exact defaults, caps, typed patterns, and no generic binary surface", () => {
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

  for (const [field, value] of [
    ["limit", 1001],
    ["offset", 100000],
    ["maxScanBytes", 512 * 1024 * 1024 + 1],
    ["contextBytes", 65],
  ] as const) {
    assert.throws(() => server.parse("nds_search_pattern", {
      rom: "game.nds",
      pattern: { kind: "byte-signature", signature: "AA" },
      scope: { kind: "whole-rom" },
      [field]: value,
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

test("disassembly handlers decode canonical ARM instructions and CFG returns", async () => {
  const { fixture, rom } = await buildDisassemblyRom();
  const server = register(fixture.directory);

  const linearResult = await server.invoke("nds_disassemble_range", {
    rom,
    processor: "arm9",
    runtimeAddress: 0x02000000,
    mode: "arm",
    maxInstructions: 1,
    maxBytes: 4,
  });
  assert.equal(resultIsError(linearResult), false);
  const linear = resultBody(linearResult);
  assert.equal(linear.status, "complete");
  const instructions = linear.instructions as Array<Record<string, unknown>>;
  assert.equal(instructions[0]?.mnemonic, "bx");
  assert.equal(instructions[0]?.bytesHex, "1eff2fe1");

  const cfgResult = await server.invoke("nds_analyze_control_flow", {
    rom,
    processor: "arm9",
    runtimeAddress: 0x02000000,
    mode: "arm",
    maxBlocks: 4,
    maxInstructions: 8,
    maxBytes: 32,
    maxEdges: 8,
  });
  assert.equal(resultIsError(cfgResult), false);
  const cfg = resultBody(cfgResult);
  assert.equal(cfg.status, "complete");
  const blocks = cfg.blocks as Array<Record<string, unknown>>;
  assert.equal(blocks.length, 1);
  assert.equal(blocks[0]?.stopReason, "return");
});

test("reference handlers classify direct ARM references and find xrefs", async () => {
  const { fixture, rom } = await buildReferenceRom();
  const server = register(fixture.directory);

  const listedResult = await server.invoke("nds_list_references", {
    rom,
    processor: "arm9",
    runtimeAddress: 0x02000000,
    mode: "arm",
    maxInstructions: 1,
    maxBytes: 4,
  });
  assert.equal(resultIsError(listedResult), false);
  const listed = resultBody(listedResult);
  const references = listed.references as Array<Record<string, unknown>>;
  assert.equal(references[0]?.kind, "direct-call");

  const xrefResult = await server.invoke("nds_find_xrefs", {
    rom,
    processor: "arm9",
    targetRuntimeAddress: 0x02000008,
    scope: { kind: "main" },
    maxComponents: 1,
    maxBlocks: 8,
    maxInstructions: 16,
    maxBytes: 64,
    maxEdges: 16,
    maxXrefs: 8,
  });
  assert.equal(resultIsError(xrefResult), false);
  const xrefs = resultBody(xrefResult);
  assert.equal(xrefs.status, "complete");
  assert.equal((xrefs.xrefs as Array<Record<string, unknown>>).length, 1);
});

test("pattern search handler returns overlapping canonical matches", async () => {
  const { fixture, rom } = await buildPatternRom();
  const server = register(fixture.directory);
  const result = await server.invoke("nds_search_pattern", {
    rom,
    pattern: { kind: "byte-signature", signature: "AA AA" },
    scope: { kind: "components", arm9Main: true },
    limit: 10,
  });
  assert.equal(resultIsError(result), false);
  const body = resultBody(result);
  assert.equal(body.status, "complete");
  assert.deepEqual(
    (body.matches as Array<Record<string, unknown>>).map((hit) => hit.romOffset),
    [0x200, 0x201],
  );
});

test("pattern search handler returns actionable typed errors", async () => {
  const { fixture, rom } = await buildPatternRom();
  const server = register(fixture.directory);
  const malformed = await server.invoke("nds_search_pattern", {
    rom,
    pattern: { kind: "byte-signature", signature: "GG" },
    scope: { kind: "whole-rom" },
  });
  assert.equal(resultIsError(malformed), true);
  assert.equal(resultBody(malformed).category, "invalid-pattern");
  assert.equal(typeof resultBody(malformed).correctiveAction, "string");

  const emptyScope = await server.invoke("nds_search_pattern", {
    rom,
    pattern: { kind: "byte-signature", signature: "AA" },
    scope: { kind: "components" },
  });
  assert.equal(resultIsError(emptyScope), true);
  assert.equal(resultBody(emptyScope).category, "invalid-pattern-scope");
});

test("pattern search respects the shared serialized output ceiling", async () => {
  const { fixture, rom } = await buildPatternRom();
  const server = register(fixture.directory, 200);
  const result = await server.invoke("nds_search_pattern", {
    rom,
    pattern: { kind: "byte-signature", signature: "AA" },
    scope: { kind: "components", arm9Main: true },
    contextBytes: 8,
  });
  assert.equal(resultIsError(result), true);
  assert.equal(resultBody(result).category, "output-bound-exceeded");
});

test("xref handler rejects missing or duplicate target selectors before scanning", async () => {
  const { fixture, rom } = await buildReferenceRom();
  const server = register(fixture.directory);

  const missing = await server.invoke("nds_find_xrefs", {
    rom,
    processor: "arm9",
    scope: { kind: "main" },
  });
  assert.equal(resultIsError(missing), true);
  assert.equal(resultBody(missing).category, "range-out-of-bounds");

  const duplicate = await server.invoke("nds_find_xrefs", {
    rom,
    processor: "arm9",
    targetRuntimeAddress: 0x02000008,
    targetRomOffset: 0x208,
    scope: { kind: "main" },
  });
  assert.equal(resultIsError(duplicate), true);
  assert.equal(resultBody(duplicate).category, "range-out-of-bounds");
});

test("disassembly handlers preserve compressed-overlay status as a successful result", async () => {
  const { fixture, rom } = await buildToolRom();
  const server = register(fixture.directory);
  const result = await server.invoke("nds_disassemble_range", {
    rom,
    processor: "arm9",
    runtimeAddress: 0x02200020,
    overlayId: 7,
    mode: "arm",
  });
  assert.equal(resultIsError(result), false);
  assert.equal(resultBody(result).status, "compressed-overlay-not-decodable");
});

test("disassembly handlers reject missing or duplicate location selectors structurally", async () => {
  const { fixture, rom } = await buildDisassemblyRom();
  const server = register(fixture.directory);

  const missing = await server.invoke("nds_disassemble_range", {
    rom,
    processor: "arm9",
    mode: "arm",
  });
  assert.equal(resultIsError(missing), true);
  assert.equal(resultBody(missing).category, "range-out-of-bounds");

  const duplicate = await server.invoke("nds_analyze_control_flow", {
    rom,
    processor: "arm9",
    runtimeAddress: 0x02000000,
    romOffset: 0x200,
    mode: "arm",
  });
  assert.equal(resultIsError(duplicate), true);
  assert.equal(resultBody(duplicate).category, "range-out-of-bounds");
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

test("index capability declaration includes all twelve NDS tool names", async () => {
  const source = await readFile(path.resolve("src/index.ts"), "utf8");
  for (const name of EXPECTED_TOOLS) {
    assert.equal(source.includes(`\"${name}\"`), true, name);
  }
});
