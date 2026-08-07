import assert from "node:assert/strict";
import test from "node:test";

import type {
  ArmDisassemblyBackend,
  ArmMode,
  DecodedArmInstruction,
} from "../src/services/disassembly/backend.js";
import {
  discoverNdsFunctions,
  type FunctionDiscoveryLimits,
} from "../src/services/nds/function-discovery.js";
import { readNdsRomMap } from "../src/services/nds/rom-map.js";
import {
  createNdsFixture,
  writeFatEntry,
  writeOverlayRecord,
} from "./helpers/nds-fixture.js";

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

function instruction(
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
    pcRelative: null,
    ...overrides,
  };
}

function call(
  address: number,
  target: number,
  switchesMode = false,
): DecodedArmInstruction {
  return instruction(address, {
    mnemonic: switchesMode ? "blx" : "bl",
    operandsText: `#0x${target.toString(16)}`,
    operands: [{ kind: "immediate", value: target }],
    isCall: true,
    switchesMode,
  });
}

function branch(
  address: number,
  target: number,
  conditional = false,
): DecodedArmInstruction {
  return instruction(address, {
    mnemonic: conditional ? "bne" : "b",
    operandsText: `#0x${target.toString(16)}`,
    operands: [{ kind: "immediate", value: target }],
    isJump: true,
    isConditional: conditional,
  });
}

function indirectCall(address: number): DecodedArmInstruction {
  return instruction(address, {
    mnemonic: "blx",
    operandsText: "r3",
    operands: [{ kind: "register", name: "r3" }],
    isCall: true,
    switchesMode: true,
  });
}

function returned(address: number, size: 2 | 4 = 4): DecodedArmInstruction {
  return instruction(address, {
    size,
    bytes: size === 2 ? [0x70, 0x47] : [0x1e, 0xff, 0x2f, 0xe1],
    mnemonic: "bx",
    operandsText: "lr",
    operands: [{ kind: "register", name: "lr" }],
    isJump: true,
    isReturn: true,
  });
}

const LIMITS: FunctionDiscoveryLimits = {
  maxComponents: 32,
  maxFunctions: 128,
  maxCallSites: 512,
  maxTotalBlocks: 512,
  maxTotalInstructions: 4096,
  maxTotalBytes: 32768,
  maxTotalEdges: 2048,
  perFunctionCfg: {
    maxBlocks: 64,
    maxInstructions: 512,
    maxBytes: 2048,
    maxEdges: 128,
  },
};

function limits(
  overrides: Partial<FunctionDiscoveryLimits>,
): FunctionDiscoveryLimits {
  return {
    ...LIMITS,
    ...overrides,
    perFunctionCfg: {
      ...LIMITS.perFunctionCfg,
      ...(overrides.perFunctionCfg ?? {}),
    },
  };
}

function functionIds(result: Awaited<ReturnType<typeof discoverNdsFunctions>>): string[] {
  return result.functions.map((entry) => entry.id);
}

test("discover NDS functions follows only proven direct-call entries", async () => {
  const fixture = await createNdsFixture({ arm9Size: 0x80 });
  const map = await readNdsRomMap(fixture.romPath);
  const backend = new FakeBackend(new Map([
    [0x02000000, call(0x02000000, 0x02000010)],
    [0x02000004, returned(0x02000004)],
    [0x02000010, call(0x02000010, 0x02000020)],
    [0x02000014, returned(0x02000014)],
    [0x02000020, returned(0x02000020)],
  ]));

  const result = await discoverNdsFunctions(
    map,
    { processor: "arm9", scope: { kind: "main" }, seeds: [] },
    LIMITS,
    backend,
  );

  assert.equal(result.status, "complete");
  assert.deepEqual(functionIds(result), [
    "arm9:main:02000000:arm",
    "arm9:main:02000010:arm",
    "arm9:main:02000020:arm",
  ]);
  assert.deepEqual(
    result.calls.map((edge) => [
      edge.callerFunctionId,
      edge.instructionAddress,
      edge.calleeFunctionId,
    ]),
    [
      ["arm9:main:02000000:arm", 0x02000000, "arm9:main:02000010:arm"],
      ["arm9:main:02000010:arm", 0x02000010, "arm9:main:02000020:arm"],
    ],
  );
  assert.deepEqual(result.functions[0]?.evidence.map((proof) => proof.kind), ["program-entry"]);
  assert.deepEqual(result.functions[1]?.evidence.map((proof) => proof.kind), ["direct-call"]);
  assert.equal(result.functions[1]?.directCallerCount, 1);
  assert.equal(result.functions[1]?.directCallSiteCount, 1);
  assert.equal(result.functions[2]?.cfg.returnSites, 1);
});

test("calls in branch-reachable blocks prove functions while branch targets do not", async () => {
  const fixture = await createNdsFixture({ arm9Size: 0x80 });
  const map = await readNdsRomMap(fixture.romPath);
  const backend = new FakeBackend(new Map([
    [0x02000000, branch(0x02000000, 0x02000008, true)],
    [0x02000004, returned(0x02000004)],
    [0x02000008, call(0x02000008, 0x02000020)],
    [0x0200000c, returned(0x0200000c)],
    [0x02000020, returned(0x02000020)],
  ]));

  const result = await discoverNdsFunctions(
    map,
    { processor: "arm9", scope: { kind: "main" }, seeds: [] },
    LIMITS,
    backend,
  );

  assert.deepEqual(functionIds(result), [
    "arm9:main:02000000:arm",
    "arm9:main:02000020:arm",
  ]);
  assert.equal(result.calls[0]?.instructionAddress, 0x02000008);
});

test("indirect calls and returns never create proven functions", async () => {
  const fixture = await createNdsFixture({ arm9Size: 0x40 });
  const map = await readNdsRomMap(fixture.romPath);
  const backend = new FakeBackend(new Map([
    [0x02000000, branch(0x02000000, 0x02000010)],
    [0x02000010, indirectCall(0x02000010)],
    [0x02000014, returned(0x02000014)],
  ]));

  const result = await discoverNdsFunctions(
    map,
    { processor: "arm9", scope: { kind: "main" }, seeds: [] },
    LIMITS,
    backend,
  );

  assert.deepEqual(functionIds(result), ["arm9:main:02000000:arm"]);
  assert.equal(result.calls.length, 0);
  assert.equal((result.functions[0]?.cfg.unresolvedEdges ?? 0) >= 2, true);
});

test("mode-switching direct calls preserve a distinct Thumb function identity", async () => {
  const fixture = await createNdsFixture({ arm9Size: 0x40 });
  const map = await readNdsRomMap(fixture.romPath);
  const backend = new FakeBackend(new Map([
    [0x02000000, call(0x02000000, 0x02000010, true)],
    [0x02000004, returned(0x02000004)],
    [0x02000010, returned(0x02000010, 2)],
  ]));

  const result = await discoverNdsFunctions(
    map,
    { processor: "arm9", scope: { kind: "main" }, seeds: [] },
    LIMITS,
    backend,
  );

  assert.deepEqual(functionIds(result), [
    "arm9:main:02000000:arm",
    "arm9:main:02000010:thumb",
  ]);
});

test("coverage-only seed can prove a callee without becoming a function", async () => {
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
    [0x02200000, call(0x02200000, 0x02200010)],
    [0x02200004, returned(0x02200004)],
    [0x02200010, returned(0x02200010)],
  ]));

  const result = await discoverNdsFunctions(
    map,
    {
      processor: "arm9",
      scope: { kind: "overlay", overlayIds: [7] },
      seeds: [{ runtimeAddress: 0x02200000, mode: "arm", overlayId: 7 }],
    },
    LIMITS,
    backend,
  );

  assert.deepEqual(functionIds(result), ["arm9:overlay:7:02200010:arm"]);
  const proof = result.functions[0]?.evidence[0];
  assert.equal(proof?.kind, "direct-call");
  assert.equal(proof?.kind === "direct-call" ? proof.caller.functionId : "bad", null);
  assert.equal(result.calls.length, 0);
  assert.equal(result.coverage[0]?.status, "scanned");
});

test("context-resolved calls inside overlapping overlays can prove same-overlay functions", async () => {
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
  const map = await readNdsRomMap(fixture.romPath);
  const backend = new FakeBackend(new Map([
    [0x02200000, call(0x02200000, 0x02200010)],
    [0x02200004, returned(0x02200004)],
    [0x02200010, returned(0x02200010)],
  ]));

  const result = await discoverNdsFunctions(
    map,
    {
      processor: "arm9",
      scope: { kind: "overlay", overlayIds: [7] },
      seeds: [{ runtimeAddress: 0x02200000, mode: "arm", overlayId: 7 }],
    },
    LIMITS,
    backend,
  );

  assert.deepEqual(functionIds(result), ["arm9:overlay:7:02200010:arm"]);
});

test("self recursion and mutual recursion terminate on canonical function identity", async () => {
  const selfFixture = await createNdsFixture({ arm9Size: 0x40 });
  const selfMap = await readNdsRomMap(selfFixture.romPath);
  const selfBackend = new FakeBackend(new Map([
    [0x02000000, call(0x02000000, 0x02000000)],
    [0x02000004, returned(0x02000004)],
  ]));
  const self = await discoverNdsFunctions(
    selfMap,
    { processor: "arm9", scope: { kind: "main" }, seeds: [] },
    LIMITS,
    selfBackend,
  );
  assert.equal(self.functions.length, 1);
  assert.deepEqual(self.functions[0]?.evidence.map((proof) => proof.kind), [
    "program-entry",
    "direct-call",
  ]);
  assert.equal(self.calls.length, 1);

  const mutualFixture = await createNdsFixture({ arm9Size: 0x40 });
  const mutualMap = await readNdsRomMap(mutualFixture.romPath);
  const mutualBackend = new FakeBackend(new Map([
    [0x02000000, call(0x02000000, 0x02000010)],
    [0x02000004, returned(0x02000004)],
    [0x02000010, call(0x02000010, 0x02000000)],
    [0x02000014, returned(0x02000014)],
  ]));
  const mutual = await discoverNdsFunctions(
    mutualMap,
    { processor: "arm9", scope: { kind: "main" }, seeds: [] },
    LIMITS,
    mutualBackend,
  );
  assert.equal(mutual.functions.length, 2);
  assert.equal(mutual.calls.length, 2);
  assert.equal(mutual.functions[0]?.evidence.length, 2);
});

async function buildCoverageFixture() {
  const fixture = await createNdsFixture({
    fileSize: 0x6000,
    arm9Size: 0x40,
    fatSize: 24,
    arm9OverlaySize: 96,
  });
  writeFatEntry(fixture.buffer, 0x900, 0, 0x1200, 0x1280);
  writeFatEntry(fixture.buffer, 0x900, 1, 0x1300, 0x1380);
  writeFatEntry(fixture.buffer, 0x900, 2, 0x1400, 0x1480);
  const overlays = [
    { overlayId: 7, fileId: 0, ram: 0x02200000, compressed: false },
    { overlayId: 9, fileId: 1, ram: 0x02210000, compressed: true },
    { overlayId: 11, fileId: 2, ram: 0x02220000, compressed: false },
  ] as const;
  for (const [index, overlay] of overlays.entries()) {
    writeOverlayRecord(fixture.buffer, 0xa00, index, {
      overlayId: overlay.overlayId,
      ramAddress: overlay.ram,
      ramSize: 0x80,
      bssSize: 0,
      staticInitStart: 0,
      staticInitEnd: 0,
      fileId: overlay.fileId,
      compressedSize: overlay.compressed ? 0x70 : 0,
      flags: overlay.compressed ? 1 : 0,
    });
  }
  await fixture.write();
  return { fixture, map: await readNdsRomMap(fixture.romPath) };
}

test("function discovery reports scanned, unseeded, and compressed component coverage", async () => {
  const { map } = await buildCoverageFixture();
  const backend = new FakeBackend(new Map([
    [0x02000000, returned(0x02000000)],
    [0x02200000, returned(0x02200000)],
  ]));

  const result = await discoverNdsFunctions(
    map,
    {
      processor: "arm9",
      scope: { kind: "main-and-overlays", overlayIds: [7, 9, 11] },
      seeds: [{ runtimeAddress: 0x02200000, mode: "arm", overlayId: 7 }],
    },
    LIMITS,
    backend,
  );

  assert.equal(result.status, "partial-coverage");
  assert.deepEqual(
    result.coverage.map((entry) => [entry.component, entry.overlayId, entry.status]),
    [
      ["main", null, "scanned"],
      ["overlay", 7, "scanned"],
      ["overlay", 9, "compressed-overlay-not-decodable"],
      ["overlay", 11, "no-proven-seed"],
    ],
  );
});

test("a unique direct call into a selected overlay proves and scans that overlay", async () => {
  const { map } = await buildCoverageFixture();
  const backend = new FakeBackend(new Map([
    [0x02000000, call(0x02000000, 0x02200000)],
    [0x02000004, returned(0x02000004)],
    [0x02200000, returned(0x02200000)],
  ]));

  const result = await discoverNdsFunctions(
    map,
    {
      processor: "arm9",
      scope: { kind: "main-and-overlays", overlayIds: [7] },
      seeds: [],
    },
    LIMITS,
    backend,
  );

  assert.equal(result.status, "complete");
  assert.deepEqual(functionIds(result), [
    "arm9:main:02000000:arm",
    "arm9:overlay:7:02200000:arm",
  ]);
  assert.equal(result.coverage[1]?.status, "scanned");
});

test("scope selection never resolves an otherwise ambiguous overlay call", async () => {
  const fixture = await createNdsFixture({
    fileSize: 0x5000,
    arm9Size: 0x40,
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
  const map = await readNdsRomMap(fixture.romPath);
  const backend = new FakeBackend(new Map([
    [0x02000000, call(0x02000000, 0x02200000)],
    [0x02000004, returned(0x02000004)],
  ]));

  const result = await discoverNdsFunctions(
    map,
    {
      processor: "arm9",
      scope: { kind: "main-and-overlays", overlayIds: [7] },
      seeds: [],
    },
    LIMITS,
    backend,
  );

  assert.deepEqual(functionIds(result), ["arm9:main:02000000:arm"]);
  assert.equal(result.coverage[1]?.status, "no-proven-seed");
  assert.equal(result.status, "partial-coverage");
});

test("function discovery enforces component and function aggregate limits", async () => {
  const { map } = await buildCoverageFixture();
  const componentBackend = new FakeBackend(new Map([
    [0x02000000, returned(0x02000000)],
  ]));
  const componentLimited = await discoverNdsFunctions(
    map,
    {
      processor: "arm9",
      scope: { kind: "main-and-overlays", overlayIds: [7] },
      seeds: [],
    },
    limits({ maxComponents: 1 }),
    componentBackend,
  );
  assert.equal(componentLimited.status, "truncated");
  assert.deepEqual(componentLimited.truncationReasons, ["component-limit"]);
  assert.equal(componentLimited.coverage[1]?.status, "out-of-limit");

  const functionFixture = await createNdsFixture({ arm9Size: 0x40 });
  const functionMap = await readNdsRomMap(functionFixture.romPath);
  const functionBackend = new FakeBackend(new Map([
    [0x02000000, call(0x02000000, 0x02000010)],
    [0x02000004, returned(0x02000004)],
    [0x02000010, returned(0x02000010)],
  ]));
  const functionLimited = await discoverNdsFunctions(
    functionMap,
    { processor: "arm9", scope: { kind: "main" }, seeds: [] },
    limits({ maxFunctions: 1 }),
    functionBackend,
  );
  assert.equal(functionLimited.status, "truncated");
  assert.deepEqual(functionLimited.truncationReasons, ["function-limit"]);
  assert.equal(functionLimited.functions.length, 1);
});

test("function discovery enforces direct call-site aggregate limit", async () => {
  const fixture = await createNdsFixture({ arm9Size: 0x80 });
  const map = await readNdsRomMap(fixture.romPath);
  const backend = new FakeBackend(new Map([
    [0x02000000, call(0x02000000, 0x02000020)],
    [0x02000004, call(0x02000004, 0x02000030)],
    [0x02000008, returned(0x02000008)],
    [0x02000020, returned(0x02000020)],
    [0x02000030, returned(0x02000030)],
  ]));

  const result = await discoverNdsFunctions(
    map,
    { processor: "arm9", scope: { kind: "main" }, seeds: [] },
    limits({ maxCallSites: 1 }),
    backend,
  );

  assert.equal(result.status, "truncated");
  assert.deepEqual(result.truncationReasons, ["call-site-limit"]);
  assert.equal(result.totals.callSites, 1);
});

test("function discovery enforces block, instruction, byte, and edge aggregate limits", async () => {
  const blockFixture = await createNdsFixture({ arm9Size: 0x40 });
  const blockMap = await readNdsRomMap(blockFixture.romPath);
  const branchBackend = () => new FakeBackend(new Map([
    [0x02000000, branch(0x02000000, 0x02000008, true)],
    [0x02000004, returned(0x02000004)],
    [0x02000008, returned(0x02000008)],
  ]));

  const blockLimited = await discoverNdsFunctions(
    blockMap,
    { processor: "arm9", scope: { kind: "main" }, seeds: [] },
    limits({ maxTotalBlocks: 1 }),
    branchBackend(),
  );
  assert.deepEqual(blockLimited.truncationReasons, ["block-limit"]);

  const instructionFixture = await createNdsFixture({ arm9Size: 0x40 });
  const instructionMap = await readNdsRomMap(instructionFixture.romPath);
  const linearBackend = () => new FakeBackend(new Map([
    [0x02000000, instruction(0x02000000)],
    [0x02000004, returned(0x02000004)],
  ]));

  const instructionLimited = await discoverNdsFunctions(
    instructionMap,
    { processor: "arm9", scope: { kind: "main" }, seeds: [] },
    limits({ maxTotalInstructions: 1 }),
    linearBackend(),
  );
  assert.deepEqual(instructionLimited.truncationReasons, ["instruction-limit"]);

  const byteLimited = await discoverNdsFunctions(
    instructionMap,
    { processor: "arm9", scope: { kind: "main" }, seeds: [] },
    limits({ maxTotalBytes: 4 }),
    linearBackend(),
  );
  assert.deepEqual(byteLimited.truncationReasons, ["byte-limit"]);

  const edgeLimited = await discoverNdsFunctions(
    blockMap,
    { processor: "arm9", scope: { kind: "main" }, seeds: [] },
    limits({ maxTotalEdges: 1 }),
    branchBackend(),
  );
  assert.deepEqual(edgeLimited.truncationReasons, ["edge-limit"]);
});

test("function discovery preserves simultaneous aggregate truncation reasons", async () => {
  const fixture = await createNdsFixture({ arm9Size: 0x40 });
  const map = await readNdsRomMap(fixture.romPath);
  const backend = new FakeBackend(new Map([
    [0x02000000, instruction(0x02000000)],
    [0x02000004, returned(0x02000004)],
  ]));

  const result = await discoverNdsFunctions(
    map,
    { processor: "arm9", scope: { kind: "main" }, seeds: [] },
    limits({ maxTotalInstructions: 1, maxTotalBytes: 4 }),
    backend,
  );

  assert.equal(result.status, "truncated");
  assert.deepEqual(result.truncationReasons, ["instruction-limit", "byte-limit"]);
});
