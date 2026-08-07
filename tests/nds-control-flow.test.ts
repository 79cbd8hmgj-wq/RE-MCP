import assert from "node:assert/strict";
import test from "node:test";

import type {
  ArmDisassemblyBackend,
  ArmMode,
  DecodedArmInstruction,
} from "../src/services/disassembly/backend.js";
import {
  analyzeNdsControlFlow,
  type StaticControlFlowGraph,
} from "../src/services/nds/control-flow.js";
import {
  createNdsFixture,
  writeFatEntry,
  writeOverlayRecord,
} from "./helpers/nds-fixture.js";
import { readNdsRomMap } from "../src/services/nds/rom-map.js";

class FakeBackend implements ArmDisassemblyBackend {
  constructor(
    private readonly decoded: ReadonlyMap<number, DecodedArmInstruction | null>,
  ) {}

  decodeOne(
    _bytes: Uint8Array,
    address: number,
    _mode: ArmMode,
  ): DecodedArmInstruction | null {
    return this.decoded.get(address) ?? null;
  }

  close(): void {}
}

function decoded(
  address: number,
  overrides: Partial<DecodedArmInstruction> = {},
): DecodedArmInstruction {
  return {
    address,
    size: 4,
    bytes: [0x00, 0x00, 0xa0, 0xe1],
    mnemonic: "mov",
    operandsText: "r0, r0",
    operands: [],
    isJump: false,
    isCall: false,
    isReturn: false,
    isConditional: false,
    switchesMode: false,
    ...overrides,
  };
}

function branch(
  address: number,
  target: number,
  conditional = false,
  switchesMode = false,
): DecodedArmInstruction {
  return decoded(address, {
    mnemonic: conditional ? "bne" : "b",
    operandsText: `#0x${target.toString(16)}`,
    operands: [{ kind: "immediate", value: target }],
    isJump: true,
    isConditional: conditional,
    switchesMode,
  });
}

function returned(address: number, size: 2 | 4 = 4): DecodedArmInstruction {
  return decoded(address, {
    size,
    bytes: size === 2 ? [0x70, 0x47] : [0x1e, 0xff, 0x2f, 0xe1],
    mnemonic: "bx",
    operandsText: "lr",
    operands: [{ kind: "register", name: "lr" }],
    isJump: true,
    isReturn: true,
  });
}

function requireGraph(
  result: Awaited<ReturnType<typeof analyzeNdsControlFlow>>,
): StaticControlFlowGraph {
  assert.ok("blocks" in result, `Expected graph, got ${result.status}`);
  return result as StaticControlFlowGraph;
}

const DEFAULT_LIMITS = {
  maxBlocks: 64,
  maxInstructions: 512,
  maxBytes: 2048,
  maxEdges: 128,
} as const;

test("conditional branches discover taken and fallthrough basic blocks", async () => {
  const fixture = await createNdsFixture();
  const map = await readNdsRomMap(fixture.romPath);
  const backend = new FakeBackend(new Map([
    [0x02000000, branch(0x02000000, 0x02000008, true)],
    [0x02000004, returned(0x02000004)],
    [0x02000008, returned(0x02000008)],
  ]));

  const graph = requireGraph(await analyzeNdsControlFlow(
    map,
    { processor: "arm9", runtimeAddress: 0x02000000, mode: "arm" },
    DEFAULT_LIMITS,
    backend,
  ));

  assert.equal(graph.status, "complete");
  assert.equal(graph.blocks.length, 3);
  assert.deepEqual(
    graph.edges.map((edge) => [edge.type, edge.targetAddress]),
    [
      ["conditional-taken", 0x02000008],
      ["conditional-fallthrough", 0x02000004],
    ],
  );
  assert.equal(graph.blocks.filter((block) => block.stopReason === "return").length, 2);
});

test("direct and indirect calls are recorded but do not discover callees", async () => {
  const fixture = await createNdsFixture();
  const map = await readNdsRomMap(fixture.romPath);
  const backend = new FakeBackend(new Map([
    [0x02000000, decoded(0x02000000, {
      mnemonic: "bl",
      operandsText: "#0x2000020",
      operands: [{ kind: "immediate", value: 0x02000020 }],
      isCall: true,
    })],
    [0x02000004, decoded(0x02000004)],
    [0x02000008, decoded(0x02000008, {
      mnemonic: "blx",
      operandsText: "r3",
      operands: [{ kind: "register", name: "r3" }],
      isCall: true,
      switchesMode: true,
    })],
    [0x0200000c, returned(0x0200000c)],
    [0x02000020, returned(0x02000020)],
  ]));

  const graph = requireGraph(await analyzeNdsControlFlow(
    map,
    { processor: "arm9", runtimeAddress: 0x02000000, mode: "arm" },
    DEFAULT_LIMITS,
    backend,
  ));

  assert.equal(graph.blocks.length, 1);
  assert.equal(graph.blocks[0]?.instructions.length, 4);
  assert.equal(graph.calls.length, 2);
  assert.equal(graph.calls[0]?.targetAddress, 0x02000020);
  assert.equal(graph.calls[0]?.resolution?.status, "resolved");
  assert.equal(graph.calls[1]?.targetAddress, null);
  assert.equal(
    graph.unresolvedEdges.some((edge) => edge.kind === "indirect-call"),
    true,
  );
});

test("indirect branches and returns terminate their blocks without guessed targets", async () => {
  const fixture = await createNdsFixture();
  const map = await readNdsRomMap(fixture.romPath);
  const indirectBackend = new FakeBackend(new Map([
    [0x02000000, decoded(0x02000000, {
      mnemonic: "bx",
      operandsText: "r3",
      operands: [{ kind: "register", name: "r3" }],
      isJump: true,
    })],
  ]));
  const indirect = requireGraph(await analyzeNdsControlFlow(
    map,
    { processor: "arm9", runtimeAddress: 0x02000000, mode: "arm" },
    DEFAULT_LIMITS,
    indirectBackend,
  ));
  assert.equal(indirect.blocks[0]?.stopReason, "indirect");
  assert.equal(indirect.unresolvedEdges[0]?.kind, "indirect-branch");

  const returnBackend = new FakeBackend(new Map([
    [0x02000000, returned(0x02000000)],
  ]));
  const returnedGraph = requireGraph(await analyzeNdsControlFlow(
    map,
    { processor: "arm9", runtimeAddress: 0x02000000, mode: "arm" },
    DEFAULT_LIMITS,
    returnBackend,
  ));
  assert.equal(returnedGraph.blocks[0]?.stopReason, "return");
  assert.equal(returnedGraph.unresolvedEdges[0]?.kind, "return");
});

test("cycles schedule each block identity only once", async () => {
  const fixture = await createNdsFixture();
  const map = await readNdsRomMap(fixture.romPath);
  const backend = new FakeBackend(new Map([
    [0x02000000, branch(0x02000000, 0x02000008)],
    [0x02000008, branch(0x02000008, 0x02000000)],
  ]));

  const graph = requireGraph(await analyzeNdsControlFlow(
    map,
    { processor: "arm9", runtimeAddress: 0x02000000, mode: "arm" },
    DEFAULT_LIMITS,
    backend,
  ));
  assert.equal(graph.status, "complete");
  assert.equal(graph.blocks.length, 2);
  assert.equal(graph.edges.length, 2);
  assert.equal(new Set(graph.blocks.map((block) => block.id)).size, 2);
});

async function overlappingOverlayMap(compressedSecond = false) {
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
      compressedSize: overlayId === 8 && compressedSecond ? 0x70 : 0,
      flags: overlayId === 8 && compressedSecond ? 1 : 0,
    });
  }
  await fixture.write();
  return { fixture, map: await readNdsRomMap(fixture.romPath) };
}

test("a backward branch inside a selected overlapping overlay preserves that source", async () => {
  const { map } = await overlappingOverlayMap();
  const backend = new FakeBackend(new Map([
    [0x02200040, branch(0x02200040, 0x02200010)],
    [0x02200010, returned(0x02200010)],
  ]));

  const graph = requireGraph(await analyzeNdsControlFlow(
    map,
    {
      processor: "arm9",
      runtimeAddress: 0x02200040,
      overlayId: 7,
      mode: "arm",
    },
    DEFAULT_LIMITS,
    backend,
  ));
  assert.equal(graph.blocks.length, 2);
  assert.deepEqual(graph.blocks.map((block) => block.source.overlayId), [7, 7]);
});

test("unique cross-component same-processor branches traverse into uncompressed overlays", async () => {
  const fixture = await createNdsFixture({
    fileSize: 0x5000,
    fatSize: 8,
    arm9OverlaySize: 32,
  });
  writeFatEntry(fixture.buffer, 0x900, 0, 0x1200, 0x1280);
  writeOverlayRecord(fixture.buffer, 0xa00, 0, {
    overlayId: 7,
    ramAddress: 0x02200000,
    ramSize: 0x80,
    bssSize: 0,
    staticInitStart: 0,
    staticInitEnd: 0,
    fileId: 0,
    compressedSize: 0,
    flags: 0,
  });
  await fixture.write();
  const map = await readNdsRomMap(fixture.romPath);
  const backend = new FakeBackend(new Map([
    [0x02000000, branch(0x02000000, 0x02200000)],
    [0x02200000, returned(0x02200000)],
  ]));

  const graph = requireGraph(await analyzeNdsControlFlow(
    map,
    { processor: "arm9", runtimeAddress: 0x02000000, mode: "arm" },
    DEFAULT_LIMITS,
    backend,
  ));
  assert.equal(graph.blocks.length, 2);
  assert.equal(graph.blocks[1]?.source.component, "overlay");
  assert.equal(graph.blocks[1]?.source.overlayId, 7);
});

test("ambiguous and compressed branch targets are recorded but never queued", async () => {
  const overlap = await overlappingOverlayMap();
  const ambiguousBackend = new FakeBackend(new Map([
    [0x02000000, branch(0x02000000, 0x02200000)],
  ]));
  const ambiguous = requireGraph(await analyzeNdsControlFlow(
    overlap.map,
    { processor: "arm9", runtimeAddress: 0x02000000, mode: "arm" },
    DEFAULT_LIMITS,
    ambiguousBackend,
  ));
  assert.equal(ambiguous.blocks.length, 1);
  assert.equal(ambiguous.unresolvedEdges[0]?.kind, "ambiguous-code-source");
  assert.equal(ambiguous.edges[0]?.targetBlockId, null);

  const compressedFixture = await createNdsFixture({
    fileSize: 0x5000,
    fatSize: 8,
    arm9OverlaySize: 32,
  });
  writeFatEntry(compressedFixture.buffer, 0x900, 0, 0x1200, 0x1280);
  writeOverlayRecord(compressedFixture.buffer, 0xa00, 0, {
    overlayId: 9,
    ramAddress: 0x02300000,
    ramSize: 0x80,
    bssSize: 0,
    staticInitStart: 0,
    staticInitEnd: 0,
    fileId: 0,
    compressedSize: 0x70,
    flags: 1,
  });
  await compressedFixture.write();
  const compressedMap = await readNdsRomMap(compressedFixture.romPath);
  const compressedBackend = new FakeBackend(new Map([
    [0x02000000, branch(0x02000000, 0x02300000)],
  ]));
  const compressed = requireGraph(await analyzeNdsControlFlow(
    compressedMap,
    { processor: "arm9", runtimeAddress: 0x02000000, mode: "arm" },
    DEFAULT_LIMITS,
    compressedBackend,
  ));
  assert.equal(compressed.blocks.length, 1);
  assert.equal(
    compressed.unresolvedEdges[0]?.kind,
    "compressed-overlay-not-decodable",
  );
});

test("deterministic mode-switching edges create a distinct Thumb block", async () => {
  const fixture = await createNdsFixture();
  const map = await readNdsRomMap(fixture.romPath);
  const backend = new FakeBackend(new Map([
    [0x02000000, branch(0x02000000, 0x0200000a, false, true)],
    [0x0200000a, returned(0x0200000a, 2)],
  ]));

  const graph = requireGraph(await analyzeNdsControlFlow(
    map,
    { processor: "arm9", runtimeAddress: 0x02000000, mode: "arm" },
    DEFAULT_LIMITS,
    backend,
  ));
  assert.equal(graph.blocks.length, 2);
  assert.equal(graph.blocks[1]?.mode, "thumb");
  assert.equal(graph.edges[0]?.targetMode, "thumb");
});

test("each traversal limit truncates without exceeding its counter", async () => {
  const fixture = await createNdsFixture();
  const map = await readNdsRomMap(fixture.romPath);
  const sequential = new FakeBackend(new Map([
    [0x02000000, decoded(0x02000000)],
    [0x02000004, decoded(0x02000004)],
  ]));

  const instructionLimited = requireGraph(await analyzeNdsControlFlow(
    map,
    { processor: "arm9", runtimeAddress: 0x02000000, mode: "arm" },
    { ...DEFAULT_LIMITS, maxInstructions: 1 },
    sequential,
  ));
  assert.deepEqual(instructionLimited.truncationReasons, ["instruction-limit"]);
  assert.equal(instructionLimited.totals.instructions, 1);

  const byteLimited = requireGraph(await analyzeNdsControlFlow(
    map,
    { processor: "arm9", runtimeAddress: 0x02000000, mode: "arm" },
    { ...DEFAULT_LIMITS, maxBytes: 4 },
    sequential,
  ));
  assert.deepEqual(byteLimited.truncationReasons, ["byte-limit"]);
  assert.equal(byteLimited.totals.bytes, 4);

  const bothLimited = requireGraph(await analyzeNdsControlFlow(
    map,
    { processor: "arm9", runtimeAddress: 0x02000000, mode: "arm" },
    { ...DEFAULT_LIMITS, maxInstructions: 1, maxBytes: 4 },
    sequential,
  ));
  assert.deepEqual(
    bothLimited.truncationReasons,
    ["instruction-limit", "byte-limit"],
  );

  const conditionalBackend = new FakeBackend(new Map([
    [0x02000000, branch(0x02000000, 0x02000008, true)],
    [0x02000004, returned(0x02000004)],
    [0x02000008, returned(0x02000008)],
  ]));
  const edgeLimited = requireGraph(await analyzeNdsControlFlow(
    map,
    { processor: "arm9", runtimeAddress: 0x02000000, mode: "arm" },
    { ...DEFAULT_LIMITS, maxEdges: 1 },
    conditionalBackend,
  ));
  assert.deepEqual(edgeLimited.truncationReasons, ["edge-limit"]);
  assert.equal(edgeLimited.totals.edges, 1);

  const blockLimited = requireGraph(await analyzeNdsControlFlow(
    map,
    { processor: "arm9", runtimeAddress: 0x02000000, mode: "arm" },
    { ...DEFAULT_LIMITS, maxBlocks: 1 },
    conditionalBackend,
  ));
  assert.deepEqual(blockLimited.truncationReasons, ["block-limit"]);
  assert.equal(blockLimited.totals.blocks, 1);
});

test("a local decode stop does not discard already queued deterministic blocks", async () => {
  const fixture = await createNdsFixture();
  const map = await readNdsRomMap(fixture.romPath);
  const backend = new FakeBackend(new Map([
    [0x02000000, branch(0x02000000, 0x02000008, true)],
    [0x02000004, null],
    [0x02000008, returned(0x02000008)],
  ]));

  const graph = requireGraph(await analyzeNdsControlFlow(
    map,
    { processor: "arm9", runtimeAddress: 0x02000000, mode: "arm" },
    DEFAULT_LIMITS,
    backend,
  ));
  assert.equal(graph.blocks.length, 3);
  assert.equal(
    graph.blocks.some((block) => block.stopReason === "decode-stopped"),
    true,
  );
  assert.equal(
    graph.blocks.some((block) => block.stopReason === "return"),
    true,
  );
});
