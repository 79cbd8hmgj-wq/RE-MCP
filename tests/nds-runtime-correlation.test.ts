import assert from "node:assert/strict";
import test from "node:test";

import type {
  ArmDisassemblyBackend,
  ArmMode,
  DecodedArmInstruction,
} from "../src/services/disassembly/backend.js";
import { createCapstoneArmBackend } from "../src/services/disassembly/capstone.js";
import { NdsError } from "../src/services/nds/errors.js";
import { correlateNdsStopContext } from "../src/services/nds/runtime-correlation.js";
import { readNdsRomMap } from "../src/services/nds/rom-map.js";
import type { StopContext } from "../src/services/stop-context.js";
import { createCompressedArmCodeFixture } from "./helpers/nds-compressed-code-fixture.js";
import {
  createNdsFixture,
  writeFatEntry,
  writeOverlayRecord,
} from "./helpers/nds-fixture.js";

class FakeBackend implements ArmDisassemblyBackend {
  constructor(
    private readonly decoded: ReadonlyMap<string, DecodedArmInstruction | null>,
  ) {}

  decodeOne(
    _bytes: Uint8Array,
    address: number,
    mode: ArmMode,
  ): DecodedArmInstruction | null {
    return this.decoded.get(`${address.toString(16)}:${mode}`) ?? null;
  }

  close(): void {}
}

function decoded(
  address: number,
  mode: ArmMode,
  overrides: Partial<DecodedArmInstruction> = {},
): DecodedArmInstruction {
  const size = mode === "arm" ? 4 : 2;
  return {
    address,
    size,
    bytes: size === 4 ? [0x00, 0x00, 0xa0, 0xe1] : [0x00, 0x46],
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

const inertBackend: ArmDisassemblyBackend = new FakeBackend(new Map());

function stopContext(pc: number, mode: "arm" | "thumb" = "arm"): StopContext {
  const cpsr = mode === "thumb" ? 0x20 : 0;
  return {
    capturedAt: "2026-08-09T13:45:00.000Z",
    stop: { kind: "signal", signal: 5, fields: {}, raw: "S05" },
    registers: {
      r0: 0,
      r1: 1,
      r2: 2,
      r3: 3,
      r4: 4,
      r5: 5,
      r6: 6,
      r7: 7,
      r8: 8,
      r9: 9,
      r10: 10,
      r11: 11,
      r12: 12,
      sp: 0x023ff000,
      lr: 0x02000100,
      pc,
      cpsr,
      mode,
      byteOrder: "little",
      raw: "00".repeat(168),
    },
    pcWindow: { address: pc, length: 4, dataHex: "00000000" },
    stackWindow: { address: 0x023ff000, length: 4, dataHex: "00000000" },
    additionalRegions: [],
  };
}

async function buildCorrelationMap() {
  const fixture = await createNdsFixture({
    fileSize: 0x5000,
    fatSize: 24,
    arm9OverlaySize: 96,
  });
  writeFatEntry(fixture.buffer, 0x900, 0, 0x1400, 0x1500);
  writeFatEntry(fixture.buffer, 0x900, 1, 0x1600, 0x1680);
  writeFatEntry(fixture.buffer, 0x900, 2, 0x1700, 0x1780);
  writeOverlayRecord(fixture.buffer, 0xa00, 0, {
    overlayId: 12,
    ramAddress: 0x02200000,
    ramSize: 0x100,
    bssSize: 0x40,
    staticInitStart: 0,
    staticInitEnd: 0,
    fileId: 0,
    compressedSize: 0,
    flags: 0,
  });
  writeOverlayRecord(fixture.buffer, 0xa00, 1, {
    overlayId: 19,
    ramAddress: 0x02200080,
    ramSize: 0x80,
    bssSize: 0,
    staticInitStart: 0,
    staticInitEnd: 0,
    fileId: 2,
    compressedSize: 0,
    flags: 0,
  });
  writeOverlayRecord(fixture.buffer, 0xa00, 2, {
    overlayId: 27,
    ramAddress: 0x02210000,
    ramSize: 0x180,
    bssSize: 0x20,
    staticInitStart: 0,
    staticInitEnd: 0,
    fileId: 1,
    compressedSize: 0x70,
    flags: 1,
  });
  await fixture.write();
  const map = await readNdsRomMap(fixture.romPath);
  return { fixture, map };
}

async function buildMainCodeMap() {
  const fixture = await createNdsFixture({ arm9Size: 0x100 });
  Buffer.from("000000eb0000a0e11eff2fe1", "hex").copy(fixture.buffer, 0x200);
  await fixture.write();
  return { fixture, map: await readNdsRomMap(fixture.romPath) };
}

function input(
  romPath: string,
  sha256: string,
  context: StopContext,
  options: Partial<{
    nearbyInstructions: number;
    referenceLimit: number;
    maxOutputBytes: number;
    includeGhidra: boolean;
    decompileGhidraFunction: boolean;
  }> = {},
) {
  return {
    romPath,
    romDisplayPath: "fixture.nds",
    expectedRomSha256: sha256,
    stopContext: context,
    options: {
      nearbyInstructions: options.nearbyInstructions ?? 8,
      referenceLimit: options.referenceLimit ?? 16,
      maxOutputBytes: options.maxOutputBytes ?? 64 * 1024,
      includeGhidra: options.includeGhidra ?? false,
      decompileGhidraFunction: options.decompileGhidraFunction ?? false,
    },
  } as const;
}

function mainCallBackend(): ArmDisassemblyBackend {
  return new FakeBackend(new Map([
    ["2000000:arm", decoded(0x02000000, "arm", {
      bytes: [0x00, 0x00, 0x00, 0xeb],
      mnemonic: "bl",
      operandsText: "#0x2000008",
      operands: [{ kind: "immediate", value: 0x02000008 }],
      isCall: true,
    })],
    ["2000004:arm", decoded(0x02000004, "arm")],
    ["2000008:arm", decoded(0x02000008, "arm", {
      bytes: [0x1e, 0xff, 0x2f, 0xe1],
      mnemonic: "bx",
      operandsText: "lr",
      operands: [{ kind: "register", name: "lr" }],
      isJump: true,
      isReturn: true,
    })],
  ]));
}

test("correlation preserves the exact observed ARM9 PC and CPSR mode for main code", async () => {
  const { fixture, map } = await buildCorrelationMap();
  const context = stopContext(0x02000040, "thumb");

  const result = await correlateNdsStopContext(
    input(fixture.romPath, map.sha256, context),
    inertBackend,
  );

  assert.equal(result.runtimeObserved.pc, 0x02000040);
  assert.equal(result.runtimeObserved.mode, "thumb");
  assert.equal(result.runtimeObserved.cpsr, 0x20);
  assert.equal(result.rom.path, "fixture.nds");
  assert.equal(result.rom.sha256, map.sha256);
  assert.equal(result.rom.launchSha256, map.sha256);
  assert.equal(result.rom.identityMatched, true);
  assert.deepEqual(result.canonical, {
    processor: "arm9",
    status: "resolved",
    candidateCount: 1,
  });
  assert.equal(result.candidates[0]?.canonical.kind, "arm9-main");
  assert.equal(result.candidates[0]?.canonical.runtimeAddress, 0x02000040);
});

test("correlation preserves every overlapping overlay candidate without selecting a loaded overlay", async () => {
  const { fixture, map } = await buildCorrelationMap();
  const result = await correlateNdsStopContext(
    input(fixture.romPath, map.sha256, stopContext(0x02200090)),
    inertBackend,
  );

  assert.equal(result.canonical.status, "ambiguous");
  assert.equal(result.canonical.candidateCount, 2);
  assert.deepEqual(
    result.candidates.map((candidate) => candidate.canonical.overlayId),
    [12, 19],
  );
  assert.equal("loadedOverlay" in result, false);
  assert.equal("bestMatch" in result, false);
});

test("correlation retains valid compressed initialized runtime provenance", async () => {
  const { fixture, map, overlayId, runtimeAddress } = await createCompressedArmCodeFixture();
  const result = await correlateNdsStopContext(
    input(fixture.romPath, map.sha256, stopContext(runtimeAddress)),
    inertBackend,
  );

  assert.equal(result.candidates[0]?.canonical.overlayId, overlayId);
  assert.equal(result.candidates[0]?.canonical.representation, "derived-overlay");
  assert.equal(result.candidates[0]?.canonical.romOffset, null);
  assert.equal(result.candidates[0]?.canonical.compressed, true);
});

test("correlation retains BSS runtime-only provenance without decoding backing bytes", async () => {
  const { fixture, map } = await buildCorrelationMap();
  const bss = await correlateNdsStopContext(
    input(fixture.romPath, map.sha256, stopContext(0x02210190)),
    inertBackend,
  );

  assert.equal(bss.candidates[0]?.canonical.kind, "overlay-bss");
  assert.equal(bss.candidates[0]?.canonical.representation, "runtime-only");
  assert.equal(bss.candidates[0]?.canonical.romOffset, null);
  assert.equal(bss.candidates[0]?.static.status, "runtime-only");
});

test("correlation returns a successful unmapped result without inventing ownership", async () => {
  const { fixture, map } = await buildCorrelationMap();
  const result = await correlateNdsStopContext(
    input(fixture.romPath, map.sha256, stopContext(0x023f0000)),
    inertBackend,
  );

  assert.deepEqual(result.canonical, {
    processor: "arm9",
    status: "unmapped",
    candidateCount: 0,
  });
  assert.deepEqual(result.candidates, []);
});

test("correlation rejects launch-time ROM identity mismatch with a dedicated category", async () => {
  const { fixture } = await buildCorrelationMap();

  await assert.rejects(
    correlateNdsStopContext(
      input(fixture.romPath, "0".repeat(64), stopContext(0x02000040)),
      inertBackend,
    ),
    (error: unknown) =>
      error instanceof NdsError
      && error.category === "runtime-correlation-rom-identity-mismatch",
  );
});

test("correlation enforces the final serialized output ceiling", async () => {
  const { fixture, map } = await buildCorrelationMap();

  await assert.rejects(
    correlateNdsStopContext(
      input(fixture.romPath, map.sha256, stopContext(0x02000040), {
        maxOutputBytes: 1,
      }),
      inertBackend,
    ),
    (error: unknown) =>
      error instanceof NdsError
      && error.category === "runtime-correlation-output-limit",
  );
});

test("correlation attaches bounded instructions, direct references, and program-entry proof", async () => {
  const { fixture, map } = await buildMainCodeMap();
  const result = await correlateNdsStopContext(
    input(fixture.romPath, map.sha256, stopContext(0x02000000), {
      nearbyInstructions: 2,
      referenceLimit: 1,
    }),
    mainCallBackend(),
  );

  const staticResult = result.candidates[0]?.static;
  assert.equal(staticResult?.status, "available");
  if (staticResult?.status !== "available") assert.fail("Expected static evidence");
  assert.equal(staticResult.instructions.length, 2);
  assert.equal(staticResult.instructions[0]?.address, 0x02000000);
  assert.equal(staticResult.instructions[0]?.mode, "arm");
  assert.equal(staticResult.instructions[0]?.flow.kind, "call");
  assert.equal(staticResult.references.length, 1);
  assert.equal(staticResult.references[0]?.kind, "direct-call");
  assert.equal(staticResult.functionEntry.proofStatus, "proven");
  assert.equal(staticResult.functionEntry.runtimeMode, "arm");
  assert.equal(staticResult.functionEntry.staticMode, "arm");
  assert.equal(staticResult.functionEntry.modeConsistent, true);
  assert.equal(
    staticResult.functionEntry.evidence.some((proof) => proof.kind === "program-entry"),
    true,
  );
});

test("correlation recognizes an exact direct-call target as a proven function entry", async () => {
  const { fixture, map } = await buildMainCodeMap();
  const result = await correlateNdsStopContext(
    input(fixture.romPath, map.sha256, stopContext(0x02000008), {
      nearbyInstructions: 1,
      referenceLimit: 0,
    }),
    mainCallBackend(),
  );

  const staticResult = result.candidates[0]?.static;
  assert.equal(staticResult?.status, "available");
  if (staticResult?.status !== "available") assert.fail("Expected static evidence");
  assert.deepEqual(staticResult.references, []);
  assert.equal(staticResult.functionEntry.proofStatus, "proven");
  assert.equal(
    staticResult.functionEntry.evidence.some((proof) => proof.kind === "direct-call"),
    true,
  );
});

test("correlation does not promote an arbitrary mid-function PC into a proven entry", async () => {
  const { fixture, map } = await buildMainCodeMap();
  const result = await correlateNdsStopContext(
    input(fixture.romPath, map.sha256, stopContext(0x02000004), {
      nearbyInstructions: 1,
      referenceLimit: 0,
    }),
    mainCallBackend(),
  );

  const staticResult = result.candidates[0]?.static;
  assert.equal(staticResult?.status, "available");
  if (staticResult?.status !== "available") assert.fail("Expected static evidence");
  assert.notEqual(staticResult.functionEntry.proofStatus, "proven");
  assert.deepEqual(staticResult.functionEntry.evidence, []);
});

test("candidate disassembly uses the observed Thumb mode without switching to ARM", async () => {
  const { fixture, map } = await buildMainCodeMap();
  const thumbAddress = 0x02000020;
  const backend = new FakeBackend(new Map([
    [`${thumbAddress.toString(16)}:thumb`, decoded(thumbAddress, "thumb", {
      bytes: [0x00, 0x46],
      mnemonic: "mov",
      operandsText: "r0, r0",
    })],
  ]));

  const result = await correlateNdsStopContext(
    input(fixture.romPath, map.sha256, stopContext(thumbAddress, "thumb"), {
      nearbyInstructions: 1,
      referenceLimit: 0,
    }),
    backend,
  );

  const staticResult = result.candidates[0]?.static;
  assert.equal(staticResult?.status, "available");
  if (staticResult?.status !== "available") assert.fail("Expected static evidence");
  assert.equal(staticResult.instructions[0]?.address, thumbAddress);
  assert.equal(staticResult.instructions[0]?.mode, "thumb");
  assert.equal(staticResult.functionEntry.runtimeMode, "thumb");
});

test("compressed-overlay stopped code decodes from the derived runtime image without fabricating a ROM offset", async () => {
  const { fixture, map, overlayId, runtimeAddress } = await createCompressedArmCodeFixture();
  const backend = await createCapstoneArmBackend();
  try {
    const result = await correlateNdsStopContext(
      input(fixture.romPath, map.sha256, stopContext(runtimeAddress), {
        nearbyInstructions: 1,
        referenceLimit: 0,
      }),
      backend,
    );

    const candidate = result.candidates[0];
    assert.equal(candidate?.canonical.overlayId, overlayId);
    assert.equal(candidate?.canonical.representation, "derived-overlay");
    assert.equal(candidate?.canonical.romOffset, null);
    assert.equal(candidate?.static.status, "available");
    if (candidate?.static.status !== "available") assert.fail("Expected static evidence");
    assert.equal(candidate.static.instructions[0]?.address, runtimeAddress);
    assert.equal(candidate.static.instructions[0]?.romOffset, null);
    assert.equal(candidate.static.instructions[0]?.source.overlayId, overlayId);
  } finally {
    backend.close();
  }
});
