import assert from "node:assert/strict";
import test from "node:test";

import type {
  ArmDisassemblyBackend,
  ArmMode,
  DecodedArmInstruction,
} from "../src/services/disassembly/backend.js";
import { NdsError } from "../src/services/nds/errors.js";
import { compareStaticReferences } from "../src/services/nds/references.js";
import {
  findNdsXrefs,
  type ReferenceScanLimits,
} from "../src/services/nds/xrefs.js";
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

function call(address: number, target: number): DecodedArmInstruction {
  return instruction(address, {
    mnemonic: "bl",
    operandsText: `#0x${target.toString(16)}`,
    operands: [{ kind: "immediate", value: target }],
    isCall: true,
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

const LIMITS: ReferenceScanLimits = {
  maxComponents: 32,
  maxBlocks: 128,
  maxInstructions: 2048,
  maxBytes: 8192,
  maxEdges: 512,
  maxXrefs: 256,
};

test("follows direct calls for coverage and returns matching direct references", async () => {
  const fixture = await createNdsFixture({ arm9Size: 0x40 });
  const map = await readNdsRomMap(fixture.romPath);
  const backend = new FakeBackend(new Map([
    [0x02000000, call(0x02000000, 0x02000010)],
    [0x02000004, branch(0x02000004, 0x0200000c, true)],
    [0x02000008, returned(0x02000008)],
    [0x0200000c, returned(0x0200000c)],
    [0x02000010, branch(0x02000010, 0x02000018)],
    [0x02000018, returned(0x02000018)],
  ]));

  const callResult = await findNdsXrefs(
    map,
    {
      processor: "arm9",
      target: { targetRuntimeAddress: 0x02000010 },
      scope: { kind: "main" },
      seeds: [],
    },
    LIMITS,
    backend,
  );
  assert.equal(callResult.status, "complete");
  assert.equal(callResult.xrefs.length, 1);
  assert.equal(callResult.xrefs[0]?.kind, "direct-call");
  assert.equal(callResult.xrefs[0]?.source.instructionAddress, 0x02000000);

  const branchResult = await findNdsXrefs(
    map,
    {
      processor: "arm9",
      target: { targetRuntimeAddress: 0x02000018 },
      scope: { kind: "main" },
      seeds: [],
    },
    LIMITS,
    backend,
  );
  assert.equal(branchResult.status, "complete");
  assert.equal(branchResult.xrefs.length, 1);
  assert.equal(branchResult.xrefs[0]?.kind, "direct-branch");
  assert.equal(branchResult.xrefs[0]?.source.instructionAddress, 0x02000010);
  assert.equal(branchResult.coverage[0]?.status, "scanned");
});

test("indirect calls continue caller fallthrough without guessing a callee", async () => {
  const fixture = await createNdsFixture({ arm9Size: 0x20 });
  const map = await readNdsRomMap(fixture.romPath);
  const backend = new FakeBackend(new Map([
    [0x02000000, indirectCall(0x02000000)],
    [0x02000004, branch(0x02000004, 0x0200000c)],
    [0x0200000c, returned(0x0200000c)],
  ]));

  const result = await findNdsXrefs(
    map,
    {
      processor: "arm9",
      target: { targetRuntimeAddress: 0x0200000c },
      scope: { kind: "main" },
      seeds: [],
    },
    LIMITS,
    backend,
  );
  assert.equal(result.status, "complete");
  assert.equal(result.xrefs.length, 1);
  assert.equal(result.xrefs[0]?.source.instructionAddress, 0x02000004);
  assert.equal(result.scan.traversalEdges, 1);
});

async function buildOverlayCoverageFixture() {
  const fixture = await createNdsFixture({
    fileSize: 0x6000,
    arm9Size: 0x20,
    fatSize: 16,
    arm9OverlaySize: 64,
  });
  writeFatEntry(fixture.buffer, 0x900, 0, 0x1200, 0x1280);
  writeFatEntry(fixture.buffer, 0x900, 1, 0x1300, 0x1380);
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
  writeOverlayRecord(fixture.buffer, 0xa00, 1, {
    overlayId: 9,
    ramAddress: 0x02210000,
    ramSize: 0x80,
    bssSize: 0,
    staticInitStart: 0,
    staticInitEnd: 0,
    fileId: 1,
    compressedSize: 0x70,
    flags: 1,
  });
  await fixture.write();
  return { fixture, map: await readNdsRomMap(fixture.romPath) };
}

test("reports scanned and unseeded overlay coverage independent of storage representation", async () => {
  const { map } = await buildOverlayCoverageFixture();
  const backend = new FakeBackend(new Map([
    [0x02000000, returned(0x02000000)],
    [0x02200000, returned(0x02200000, 2)],
  ]));

  const seeded = await findNdsXrefs(
    map,
    {
      processor: "arm9",
      target: { targetRuntimeAddress: 0x03000000 },
      scope: { kind: "main-and-overlays", overlayIds: [7, 9] },
      seeds: [{ runtimeAddress: 0x02200000, mode: "thumb", overlayId: 7 }],
    },
    LIMITS,
    backend,
  );
  assert.equal(seeded.status, "partial-coverage");
  assert.deepEqual(
    seeded.coverage.map((entry) => [entry.component, entry.overlayId, entry.status]),
    [
      ["main", null, "scanned"],
      ["overlay", 7, "scanned"],
      ["overlay", 9, "no-proven-seed"],
    ],
  );

  const unseeded = await findNdsXrefs(
    map,
    {
      processor: "arm9",
      target: { targetRuntimeAddress: 0x03000000 },
      scope: { kind: "main-and-overlays", overlayIds: [7] },
      seeds: [],
    },
    LIMITS,
    backend,
  );
  assert.equal(unseeded.status, "partial-coverage");
  assert.equal(unseeded.coverage[1]?.status, "no-proven-seed");
});

test("component cap is deterministic and marks excluded components out-of-limit", async () => {
  const fixture = await createNdsFixture({
    fileSize: 0x7000,
    arm9Size: 0x20,
    fatSize: 24,
    arm9OverlaySize: 96,
  });
  for (const [index, overlayId] of [9, 3, 7].entries()) {
    const rom = 0x1200 + index * 0x100;
    writeFatEntry(fixture.buffer, 0x900, index, rom, rom + 0x80);
    writeOverlayRecord(fixture.buffer, 0xa00, index, {
      overlayId,
      ramAddress: 0x02200000 + index * 0x10000,
      ramSize: 0x80,
      bssSize: 0,
      staticInitStart: 0,
      staticInitEnd: 0,
      fileId: index,
      compressedSize: 0,
      flags: 0,
    });
  }
  await fixture.write();
  const map = await readNdsRomMap(fixture.romPath);
  const backend = new FakeBackend(new Map([[0x02000000, returned(0x02000000)]]));

  const result = await findNdsXrefs(
    map,
    {
      processor: "arm9",
      target: { targetRuntimeAddress: 0x03000000 },
      scope: { kind: "all-executable-components" },
      seeds: [],
    },
    { ...LIMITS, maxComponents: 2 },
    backend,
  );
  assert.equal(result.status, "truncated");
  assert.deepEqual(result.truncationReasons, ["component-limit"]);
  assert.deepEqual(
    result.coverage.slice(2).map((entry) => entry.status),
    ["out-of-limit", "out-of-limit"],
  );
});

test("retains the deterministic sorted xref prefix when result-limited", async () => {
  const fixture = await createNdsFixture({ arm9Size: 0x40 });
  const map = await readNdsRomMap(fixture.romPath);
  const target = 0x02000020;
  const backend = new FakeBackend(new Map([
    [0x02000000, call(0x02000000, 0x02000010)],
    [0x02000004, branch(0x02000004, target, true)],
    [0x02000008, branch(0x02000008, target)],
    [0x02000010, branch(0x02000010, target)],
    [0x02000020, returned(0x02000020)],
  ]));

  const all = await findNdsXrefs(
    map,
    {
      processor: "arm9",
      target: { targetRuntimeAddress: target },
      scope: { kind: "main" },
      seeds: [],
    },
    LIMITS,
    backend,
  );
  const limited = await findNdsXrefs(
    map,
    {
      processor: "arm9",
      target: { targetRuntimeAddress: target },
      scope: { kind: "main" },
      seeds: [],
    },
    { ...LIMITS, maxXrefs: 2 },
    backend,
  );

  assert.ok(all.xrefs.length >= 3);
  assert.equal(limited.status, "truncated");
  assert.equal(limited.truncationReasons.includes("result-limit"), true);
  assert.deepEqual(
    limited.xrefs,
    [...all.xrefs].sort(compareStaticReferences).slice(0, 2),
  );
});

test("global scan limits truncate and outrank independent coverage gaps", async () => {
  const { map } = await buildOverlayCoverageFixture();
  const backend = new FakeBackend(new Map([
    [0x02000000, branch(0x02000000, 0x02000008, true)],
    [0x02000004, returned(0x02000004)],
    [0x02000008, returned(0x02000008)],
  ]));
  const result = await findNdsXrefs(
    map,
    {
      processor: "arm9",
      target: { targetRuntimeAddress: 0x03000000 },
      scope: { kind: "main-and-overlays", overlayIds: [7] },
      seeds: [],
    },
    { ...LIMITS, maxBlocks: 1 },
    backend,
  );
  assert.equal(result.status, "truncated");
  assert.equal(result.truncationReasons.includes("block-limit"), true);
  assert.equal(result.coverage[1]?.status, "no-proven-seed");
});

test("rejects non-positive internal scan limits with the reference limit category", async () => {
  const fixture = await createNdsFixture();
  const map = await readNdsRomMap(fixture.romPath);
  const backend = new FakeBackend(new Map());
  const invalid = { ...LIMITS, maxEdges: 0 };

  await assert.rejects(
    () => findNdsXrefs(
      map,
      {
        processor: "arm9",
        target: { targetRuntimeAddress: 0x02000000 },
        scope: { kind: "main" },
        seeds: [],
      },
      invalid,
      backend,
    ),
    (error: unknown) => error instanceof NdsError
      && String(error.category) === "reference-scan-limit-exceeded",
  );
});
