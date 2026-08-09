import assert from "node:assert/strict";
import test from "node:test";

import { NdsError } from "../src/services/nds/errors.js";
import { resolveGhidraInspectionSelector } from "../src/services/nds/ghidra-inspection.js";
import type { NdsOverlay } from "../src/services/nds/overlays.js";
import type { NdsRomMap } from "../src/services/nds/rom-map.js";

function compressedOverlay(): NdsOverlay {
  return {
    processor: "arm9",
    overlayId: 3,
    ramAddress: 0x02210000,
    ramSize: 0x100,
    ramEnd: 0x02210100,
    bssSize: 0x20,
    bssEnd: 0x02210120,
    staticInitStart: 0,
    staticInitEnd: 0,
    fileId: 3,
    romOffset: 0x3000,
    romSize: 0x80,
    compressedSize: 0x70,
    flags: 1,
    compressed: true,
  };
}

function map(): NdsRomMap {
  const overlay = compressedOverlay();
  return {
    romPath: "/workspace/game.nds",
    fileSize: 0x10000,
    sha256: "a".repeat(64),
    sha256Prefix: "a".repeat(16),
    header: {
      gameTitle: "GHIDRA DERIVED",
      gameCode: "GHDR",
      makerCode: "01",
      unitCode: 0,
      deviceCapacity: 0,
      romVersion: 0,
      bannerOffset: 0,
      arm9: {
        romOffset: 0x200,
        entryAddress: 0x02000000,
        ramAddress: 0x02000000,
        size: 0x100,
        romEnd: 0x300,
        ramEnd: 0x02000100,
      },
      arm7: {
        romOffset: 0x600,
        entryAddress: 0x03800000,
        ramAddress: 0x03800000,
        size: 0x80,
        romEnd: 0x680,
        ramEnd: 0x03800080,
      },
      fnt: { offset: 0, size: 0, end: 0 },
      fat: { offset: 0, size: 0, end: 0 },
      arm9OverlayTable: { offset: 0, size: 0, end: 0 },
      arm7OverlayTable: { offset: 0, size: 0, end: 0 },
    },
    fat: [],
    filesystem: { directories: [], files: [] },
    overlays: { arm9: [overlay], arm7: [] },
    executableRanges: [],
  };
}

function category(expected: string) {
  return (error: unknown) => error instanceof NdsError && String(error.category) === expected;
}

test("Ghidra selector accepts initialized compressed overlays as derived runtime code", () => {
  const canonical = map();
  for (const operation of ["inspect-function", "decompile-function", "list-calls"] as const) {
    const selected = resolveGhidraInspectionSelector(
      canonical,
      { processor: "arm9", runtimeAddress: 0x02210020, overlayId: 3 },
      operation,
    );
    assert.equal(selected.component, "overlay");
    assert.equal(selected.overlayId, 3);
    assert.equal(selected.addressSpace, "RE_MCP_ARM9_OVL_3");
    assert.equal(selected.fileBacked, false,
      "decoded runtime bytes must never be represented as physical ROM-backed bytes");
    assert.equal(selected.bss, false);
    assert.equal(selected.compressed, true);
  }
});

test("Ghidra selector still rejects compressed-overlay BSS for function/decompile/call operations", () => {
  const canonical = map();
  const bssReference = resolveGhidraInspectionSelector(
    canonical,
    { processor: "arm9", runtimeAddress: 0x02210108, overlayId: 3 },
    "list-references",
  );
  assert.equal(bssReference.component, "overlay");
  assert.equal(bssReference.bss, true);
  assert.equal(bssReference.fileBacked, false);
  assert.equal(bssReference.compressed, true);

  for (const operation of ["inspect-function", "decompile-function", "list-calls"] as const) {
    assert.throws(
      () => resolveGhidraInspectionSelector(
        canonical,
        { processor: "arm9", runtimeAddress: 0x02210108, overlayId: 3 },
        operation,
      ),
      category("ghidra-address-not-inspectable"),
    );
  }
});
