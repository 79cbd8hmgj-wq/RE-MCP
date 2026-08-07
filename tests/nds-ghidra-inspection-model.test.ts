import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";

import {
  GHIDRA_INSPECTION_FORMAT,
  GHIDRA_INSPECTION_FORMAT_VERSION,
  clampDecompilerCharacters,
  clampInspectionPage,
  ghidraInspectionRequestPath,
  ghidraInspectionResultPath,
  ghidraInspectionRoot,
  validateCallDirection,
  validateInspectionRequestId,
  validateReferenceDirection,
  validateSymbolMatch,
  validateSymbolQuery,
  type GhidraCanonicalAddressIdentity,
  type GhidraInspectionOperation,
} from "../src/services/nds/ghidra-inspection-model.js";
import type { NdsRomMap } from "../src/services/nds/rom-map.js";

const SHA = "a".repeat(64);
const PREFIX = SHA.slice(0, 16);

function map(): NdsRomMap {
  return {
    romPath: "/workspace/game.nds",
    fileSize: 0x10000,
    sha256: SHA,
    sha256Prefix: PREFIX,
    header: {
      gameTitle: "INSPECT",
      gameCode: "INSP",
      makerCode: "01",
      unitCode: 0,
      deviceCapacity: 0,
      romVersion: 0,
      bannerOffset: 0,
      arm9: {
        romOffset: 0x4000,
        entryAddress: 0x02000000,
        ramAddress: 0x02000000,
        size: 0x100,
        romEnd: 0x4100,
        ramEnd: 0x02000100,
      },
      arm7: {
        romOffset: 0x5000,
        entryAddress: 0x03800000,
        ramAddress: 0x03800000,
        size: 0x80,
        romEnd: 0x5080,
        ramEnd: 0x03800080,
      },
      fnt: { offset: 0, size: 0, end: 0 },
      fat: { offset: 0, size: 0, end: 0 },
      arm9OverlayTable: { offset: 0, size: 0, end: 0 },
      arm7OverlayTable: { offset: 0, size: 0, end: 0 },
    },
    fat: [],
    filesystem: { directories: [], files: [] },
    overlays: { arm9: [], arm7: [] },
    executableRanges: [],
  };
}

test("Ghidra inspection model exposes one fixed format and five operations", () => {
  assert.equal(GHIDRA_INSPECTION_FORMAT, "re-mcp-nds-ghidra-inspection");
  assert.equal(GHIDRA_INSPECTION_FORMAT_VERSION, 1);
  const operations: readonly GhidraInspectionOperation[] = [
    "inspect-function",
    "decompile-function",
    "search-symbols",
    "list-references",
    "list-calls",
  ];
  assert.equal(operations.length, 5);
});

test("Ghidra inspection request IDs are fixed lowercase hex and cannot escape paths", () => {
  assert.equal(validateInspectionRequestId("a1b2c3d4e5f6a7b8"), "a1b2c3d4e5f6a7b8");
  for (const value of ["../escape", "A1B2C3D4E5F6A7B8", "abcd", "g1b2c3d4e5f6a7b8", "a".repeat(17)]) {
    assert.throws(() => validateInspectionRequestId(value), /request id/i);
  }
});

test("Ghidra inspection transport paths stay beneath the deterministic generated root", () => {
  const root = ghidraInspectionRoot(map(), "/workspace");
  assert.equal(root, path.join("/workspace", "analysis", "generated", "nds", PREFIX, "ghidra-inspection"));
  const request = ghidraInspectionRequestPath(map(), "/workspace", "0123456789abcdef");
  const result = ghidraInspectionResultPath(map(), "/workspace", "0123456789abcdef");
  assert.equal(request, path.join(root, "0123456789abcdef.request.json"));
  assert.equal(result, path.join(root, "0123456789abcdef.result.json"));
  assert.equal(path.relative(root, request).startsWith(".."), false);
  assert.equal(path.relative(root, result).startsWith(".."), false);
});

test("Ghidra inspection pagination and decompiler text bounds are strict", () => {
  assert.deepEqual(clampInspectionPage(undefined, undefined), { limit: 100, offset: 0 });
  assert.deepEqual(clampInspectionPage(1000, 100000), { limit: 1000, offset: 100000 });
  assert.throws(() => clampInspectionPage(0, 0), /limit/i);
  assert.throws(() => clampInspectionPage(1001, 0), /limit/i);
  assert.throws(() => clampInspectionPage(100, -1), /offset/i);
  assert.throws(() => clampInspectionPage(100, 100001), /offset/i);

  assert.equal(clampDecompilerCharacters(undefined), 20000);
  assert.equal(clampDecompilerCharacters(1), 1);
  assert.equal(clampDecompilerCharacters(100000), 100000);
  assert.throws(() => clampDecompilerCharacters(0), /maxCharacters/i);
  assert.throws(() => clampDecompilerCharacters(100001), /maxCharacters/i);
});

test("Ghidra inspection symbol and direction inputs expose no regex or arbitrary expression mode", () => {
  assert.equal(validateSymbolQuery("Main"), "Main");
  assert.equal(validateSymbolQuery("é"), "é");
  assert.throws(() => validateSymbolQuery(""), /query/i);
  assert.throws(() => validateSymbolQuery("x".repeat(129)), /query/i);

  assert.equal(validateSymbolMatch(undefined), "prefix");
  assert.equal(validateSymbolMatch("exact"), "exact");
  assert.equal(validateSymbolMatch("contains"), "contains");
  assert.throws(() => validateSymbolMatch("regex"), /match/i);

  assert.equal(validateReferenceDirection(undefined), "both");
  assert.equal(validateReferenceDirection("from"), "from");
  assert.equal(validateReferenceDirection("to"), "to");
  assert.throws(() => validateReferenceDirection("recursive"), /direction/i);

  assert.equal(validateCallDirection(undefined), "both");
  assert.equal(validateCallDirection("callers"), "callers");
  assert.equal(validateCallDirection("callees"), "callees");
  assert.throws(() => validateCallDirection("graph"), /direction/i);
});

test("main inspection identity uses the current Ghidra default space while overlays use explicit owned spaces", () => {
  const main: GhidraCanonicalAddressIdentity = {
    processor: "arm9",
    runtimeAddress: 0x02000000,
    component: "main",
    overlayId: null,
    addressSpace: null,
    fileBacked: true,
    bss: false,
    compressed: false,
  };
  const overlay: GhidraCanonicalAddressIdentity = {
    processor: "arm9",
    runtimeAddress: 0x02001000,
    component: "overlay",
    overlayId: 7,
    addressSpace: "RE_MCP_ARM9_OVL_7",
    fileBacked: true,
    bss: false,
    compressed: false,
  };
  assert.equal(main.addressSpace, null);
  assert.equal(overlay.addressSpace, "RE_MCP_ARM9_OVL_7");
});
