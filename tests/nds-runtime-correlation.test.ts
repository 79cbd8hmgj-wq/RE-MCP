import assert from "node:assert/strict";
import test from "node:test";

import type { ArmDisassemblyBackend, ArmMode } from "../src/services/disassembly/backend.js";
import { NdsError } from "../src/services/nds/errors.js";
import { correlateNdsStopContext } from "../src/services/nds/runtime-correlation.js";
import { readNdsRomMap } from "../src/services/nds/rom-map.js";
import type { StopContext } from "../src/services/stop-context.js";
import {
  createNdsFixture,
  writeFatEntry,
  writeOverlayRecord,
} from "./helpers/nds-fixture.js";

const inertBackend: ArmDisassemblyBackend = {
  decodeOne(_bytes: Uint8Array, _address: number, _mode: ArmMode) {
    return null;
  },
  close() {},
};

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

function input(
  romPath: string,
  sha256: string,
  context: StopContext,
  maxOutputBytes = 64 * 1024,
) {
  return {
    romPath,
    romDisplayPath: "fixture.nds",
    expectedRomSha256: sha256,
    stopContext: context,
    options: {
      nearbyInstructions: 8,
      referenceLimit: 16,
      maxOutputBytes,
      includeGhidra: false,
      decompileGhidraFunction: false,
    },
  } as const;
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

test("correlation retains compressed initialized and BSS runtime provenance", async () => {
  const { fixture, map } = await buildCorrelationMap();

  const compressed = await correlateNdsStopContext(
    input(fixture.romPath, map.sha256, stopContext(0x02210040)),
    inertBackend,
  );
  assert.equal(compressed.candidates[0]?.canonical.overlayId, 27);
  assert.equal(compressed.candidates[0]?.canonical.representation, "derived-overlay");
  assert.equal(compressed.candidates[0]?.canonical.romOffset, null);
  assert.equal(compressed.candidates[0]?.canonical.compressed, true);

  const bss = await correlateNdsStopContext(
    input(fixture.romPath, map.sha256, stopContext(0x02210190)),
    inertBackend,
  );
  assert.equal(bss.candidates[0]?.canonical.kind, "overlay-bss");
  assert.equal(bss.candidates[0]?.canonical.representation, "runtime-only");
  assert.equal(bss.candidates[0]?.canonical.romOffset, null);
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
      input(fixture.romPath, map.sha256, stopContext(0x02000040), 1),
      inertBackend,
    ),
    (error: unknown) =>
      error instanceof NdsError
      && error.category === "runtime-correlation-output-limit",
  );
});
