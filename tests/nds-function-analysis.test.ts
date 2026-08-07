import assert from "node:assert/strict";
import test from "node:test";

import type {
  ArmDisassemblyBackend,
  ArmMode,
  DecodedArmInstruction,
} from "../src/services/disassembly/backend.js";
import {
  analyzeNdsFunction,
  type AnalyzeFunctionLimits,
} from "../src/services/nds/function-analysis.js";
import { NdsError } from "../src/services/nds/errors.js";
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
    bytes: [0, 0, 0, 0],
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

function branch(address: number, target: number): DecodedArmInstruction {
  return instruction(address, {
    mnemonic: "b",
    operandsText: `#0x${target.toString(16)}`,
    operands: [{ kind: "immediate", value: target }],
    isJump: true,
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

const LIMITS: AnalyzeFunctionLimits = {
  proof: {
    maxComponents: 32,
    maxBlocks: 128,
    maxInstructions: 2048,
    maxBytes: 8192,
    maxEdges: 512,
    maxXrefs: 256,
  },
  cfg: {
    maxBlocks: 64,
    maxInstructions: 512,
    maxBytes: 2048,
    maxEdges: 128,
  },
};

function limits(
  proofOverrides: Partial<AnalyzeFunctionLimits["proof"]> = {},
): AnalyzeFunctionLimits {
  return {
    proof: { ...LIMITS.proof, ...proofOverrides },
    cfg: LIMITS.cfg,
  };
}

function categoryOf(error: unknown): string | null {
  return error instanceof NdsError ? String(error.category) : null;
}

test("analyze NDS function proves program entry and direct-call target", async () => {
  const fixture = await createNdsFixture({ arm9Size: 0x80 });
  const map = await readNdsRomMap(fixture.romPath);
  const decoded = new Map<number, DecodedArmInstruction | null>([
    [0x02000000, call(0x02000000, 0x02000010)],
    [0x02000004, returned(0x02000004)],
    [0x02000010, returned(0x02000010)],
  ]);

  const entry = await analyzeNdsFunction(
    map,
    {
      processor: "arm9",
      runtimeAddress: 0x02000000,
      mode: "arm",
      proofScope: { kind: "main" },
      seeds: [],
    },
    LIMITS,
    new FakeBackend(decoded),
  );
  assert.equal(entry.proofStatus, "proven");
  assert.equal(entry.evidence.some((proof) => proof.kind === "program-entry"), true);
  assert.ok(entry.cfg);
  assert.equal(entry.outgoingCalls.length, 1);
  assert.deepEqual(entry.returnSites, [0x02000004]);

  const callee = await analyzeNdsFunction(
    map,
    {
      processor: "arm9",
      runtimeAddress: 0x02000010,
      mode: "arm",
      proofScope: { kind: "main" },
      seeds: [],
    },
    LIMITS,
    new FakeBackend(decoded),
  );
  assert.equal(callee.proofStatus, "proven");
  assert.deepEqual(callee.evidence.map((proof) => proof.kind), ["direct-call"]);
  assert.equal(callee.callers.length, 1);
  assert.equal(
    callee.callers[0]?.kind === "direct-call"
      ? callee.callers[0].caller.instructionAddress
      : null,
    0x02000000,
  );
  assert.ok(callee.cfg);
  assert.deepEqual(callee.returnSites, [0x02000010]);
});

test("focused proof requires exact direct-call target mode", async () => {
  const fixture = await createNdsFixture({ arm9Size: 0x40 });
  const map = await readNdsRomMap(fixture.romPath);
  const decoded = new Map<number, DecodedArmInstruction | null>([
    [0x02000000, call(0x02000000, 0x02000010, true)],
    [0x02000004, returned(0x02000004)],
    [0x02000010, returned(0x02000010, 2)],
  ]);

  const arm = await analyzeNdsFunction(
    map,
    {
      processor: "arm9",
      runtimeAddress: 0x02000010,
      mode: "arm",
      proofScope: { kind: "main" },
      seeds: [],
    },
    LIMITS,
    new FakeBackend(decoded),
  );
  assert.equal(arm.proofStatus, "not-proven-function-entry");
  assert.equal(arm.cfg, null);

  const thumb = await analyzeNdsFunction(
    map,
    {
      processor: "arm9",
      runtimeAddress: 0x02000010,
      mode: "thumb",
      proofScope: { kind: "main" },
      seeds: [],
    },
    LIMITS,
    new FakeBackend(decoded),
  );
  assert.equal(thumb.proofStatus, "proven");
  assert.equal(thumb.entry.mode, "thumb");
});

test("direct branch evidence is a complete negative for function proof", async () => {
  const fixture = await createNdsFixture({ arm9Size: 0x40 });
  const map = await readNdsRomMap(fixture.romPath);
  const backend = new FakeBackend(new Map([
    [0x02000000, branch(0x02000000, 0x02000010)],
    [0x02000010, returned(0x02000010)],
  ]));

  const result = await analyzeNdsFunction(
    map,
    {
      processor: "arm9",
      runtimeAddress: 0x02000010,
      mode: "arm",
      proofScope: { kind: "main" },
      seeds: [],
    },
    LIMITS,
    backend,
  );

  assert.equal(result.proofStatus, "not-proven-function-entry");
  assert.equal(result.proofSearch.status, "complete");
  assert.deepEqual(result.evidence, []);
  assert.equal(result.cfg, null);
});

test("truncated proof search returns proof-inconclusive rather than a false negative", async () => {
  const fixture = await createNdsFixture({ arm9Size: 0x40 });
  const map = await readNdsRomMap(fixture.romPath);
  const backend = new FakeBackend(new Map([
    [0x02000000, instruction(0x02000000)],
    [0x02000004, returned(0x02000004)],
  ]));

  const result = await analyzeNdsFunction(
    map,
    {
      processor: "arm9",
      runtimeAddress: 0x02000010,
      mode: "arm",
      proofScope: { kind: "main" },
      seeds: [],
    },
    limits({ maxInstructions: 1 }),
    backend,
  );

  assert.equal(result.proofStatus, "proof-inconclusive");
  assert.equal(result.proofSearch.status, "truncated");
  assert.equal(result.proofSearch.truncationReasons.includes("instruction-limit"), true);
  assert.equal(result.cfg, null);
});

async function buildOverlayFixture(compressed = false) {
  const fixture = await createNdsFixture({
    fileSize: 0x5000,
    arm9Size: 0x80,
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
    compressedSize: compressed ? 0x70 : 0,
    flags: compressed ? 1 : 0,
  });
  await fixture.write();
  return { fixture, map: await readNdsRomMap(fixture.romPath) };
}

test("positive proof remains proven when unrelated selected coverage is incomplete", async () => {
  const { map } = await buildOverlayFixture();
  const backend = new FakeBackend(new Map([
    [0x02000000, call(0x02000000, 0x02000010)],
    [0x02000004, returned(0x02000004)],
    [0x02000010, returned(0x02000010)],
  ]));

  const result = await analyzeNdsFunction(
    map,
    {
      processor: "arm9",
      runtimeAddress: 0x02000010,
      mode: "arm",
      proofScope: { kind: "main-and-overlays", overlayIds: [7] },
      seeds: [],
    },
    LIMITS,
    backend,
  );

  assert.equal(result.proofStatus, "proven");
  assert.equal(result.proofSearch.status, "partial-coverage");
  assert.equal(result.proofSearch.coverage[1]?.status, "no-proven-seed");
  assert.ok(result.cfg);
});

test("unseeded or compressed proof scope returns proof-inconclusive when no proof exists", async () => {
  const unseeded = await buildOverlayFixture(false);
  const unseededResult = await analyzeNdsFunction(
    unseeded.map,
    {
      processor: "arm9",
      runtimeAddress: 0x02000010,
      mode: "arm",
      proofScope: { kind: "overlay", overlayIds: [7] },
      seeds: [],
    },
    LIMITS,
    new FakeBackend(new Map()),
  );
  assert.equal(unseededResult.proofStatus, "proof-inconclusive");
  assert.equal(unseededResult.proofSearch.status, "partial-coverage");
  assert.equal(unseededResult.proofSearch.coverage[0]?.status, "no-proven-seed");

  const compressed = await buildOverlayFixture(true);
  const compressedResult = await analyzeNdsFunction(
    compressed.map,
    {
      processor: "arm9",
      runtimeAddress: 0x02000010,
      mode: "arm",
      proofScope: { kind: "overlay", overlayIds: [7] },
      seeds: [],
    },
    LIMITS,
    new FakeBackend(new Map()),
  );
  assert.equal(compressedResult.proofStatus, "proof-inconclusive");
  assert.equal(
    compressedResult.proofSearch.coverage[0]?.status,
    "compressed-overlay-not-decodable",
  );
});

test("focused proof reconstructs contextual overlay ownership from a proven direct call", async () => {
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
  const decoded = new Map<number, DecodedArmInstruction | null>([
    [0x02200000, call(0x02200000, 0x02200010)],
    [0x02200004, returned(0x02200004)],
    [0x02200010, returned(0x02200010)],
  ]);

  const result = await analyzeNdsFunction(
    map,
    {
      processor: "arm9",
      runtimeAddress: 0x02200010,
      mode: "arm",
      overlayId: 7,
      proofScope: { kind: "overlay", overlayIds: [7] },
      seeds: [{ runtimeAddress: 0x02200000, mode: "arm", overlayId: 7 }],
    },
    LIMITS,
    new FakeBackend(decoded),
  );

  assert.equal(result.proofStatus, "proven");
  assert.equal(result.entry.overlayId, 7);
  assert.equal(result.callers.length, 1);
  assert.ok(result.cfg);
});

test("ambiguous requested function entry fails rather than guessing an overlay", async () => {
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

  await assert.rejects(
    () => analyzeNdsFunction(
      map,
      {
        processor: "arm9",
        runtimeAddress: 0x02200010,
        mode: "arm",
        proofScope: { kind: "main" },
        seeds: [],
      },
      LIMITS,
      new FakeBackend(new Map()),
    ),
    (error: unknown) => {
      assert.equal(categoryOf(error), "function-entry-not-uniquely-resolved");
      return true;
    },
  );
});
