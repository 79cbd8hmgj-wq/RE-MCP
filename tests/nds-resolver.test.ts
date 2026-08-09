import assert from "node:assert/strict";
import test from "node:test";

import { NdsError } from "../src/services/nds/errors.js";
import { resolveRomOffset, resolveRuntimeAddress } from "../src/services/nds/resolver.js";
import { readNdsRomMap } from "../src/services/nds/rom-map.js";
import {
  createNdsFixture,
  writeFatEntry,
  writeOverlayRecord,
} from "./helpers/nds-fixture.js";

async function buildResolverMap() {
  const fixture = await createNdsFixture({
    fileSize: 0x5000,
    fatSize: 24,
    arm9OverlaySize: 96,
  });
  writeFatEntry(fixture.buffer, 0x900, 0, 0x1400, 0x1500);
  writeFatEntry(fixture.buffer, 0x900, 1, 0x1600, 0x1680);
  writeFatEntry(fixture.buffer, 0x900, 2, 0x1700, 0x1780);
  writeOverlayRecord(fixture.buffer, 0xa00, 0, {
    overlayId: 10,
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
    overlayId: 20,
    ramAddress: 0x02210000,
    ramSize: 0x180,
    bssSize: 0x20,
    staticInitStart: 0,
    staticInitEnd: 0,
    fileId: 1,
    compressedSize: 0x70,
    flags: 1,
  });
  writeOverlayRecord(fixture.buffer, 0xa00, 2, {
    overlayId: 30,
    ramAddress: 0x02200080,
    ramSize: 0x80,
    bssSize: 0,
    staticInitStart: 0,
    staticInitEnd: 0,
    fileId: 2,
    compressedSize: 0,
    flags: 0,
  });
  await fixture.write();
  return { fixture, map: await readNdsRomMap(fixture.romPath) };
}

test("resolves ARM9 main runtime addresses directly to ROM bytes", async () => {
  const { map } = await buildResolverMap();
  assert.deepEqual(resolveRuntimeAddress(map, 0x02000040, "arm9"), {
    status: "resolved",
    candidate: {
      kind: "arm9-main",
      processor: "arm9",
      runtimeAddress: 0x02000040,
      relativeOffset: 0x40,
      runtimeImageOffset: 0x40,
      representation: "rom-file-backed",
      overlayId: null,
      fileId: null,
      romOffset: 0x240,
      backingRomOffset: 0x200,
      backingRomSize: 0x200,
      compressed: false,
    },
  });
});

test("resolves a single uncompressed overlay byte directly to its backing ROM byte", async () => {
  const { map } = await buildResolverMap();
  const result = resolveRuntimeAddress(map, 0x02200020, "arm9");
  assert.equal(result.status, "resolved");
  if (result.status !== "resolved") assert.fail();
  assert.equal(result.candidate.overlayId, 10);
  assert.equal(result.candidate.romOffset, 0x1420);
});

test("does not fabricate a direct ROM byte for compressed runtime overlay data", async () => {
  const { map } = await buildResolverMap();
  const result = resolveRuntimeAddress(map, 0x02210040, "arm9");
  assert.equal(result.status, "compressed-no-direct-rom-mapping");
  if (result.status !== "compressed-no-direct-rom-mapping") assert.fail();
  assert.equal(result.candidate.overlayId, 20);
  assert.equal(result.candidate.romOffset, null);
  assert.equal(result.candidate.backingRomOffset, 0x1600);
  assert.equal(result.candidate.backingRomSize, 0x80);
});

test("reports overlay BSS as runtime-only", async () => {
  const { map } = await buildResolverMap();
  const result = resolveRuntimeAddress(map, 0x02200120, "arm9");
  assert.equal(result.status, "runtime-only-bss");
  if (result.status !== "runtime-only-bss") assert.fail();
  assert.equal(result.candidate.kind, "overlay-bss");
  assert.equal(result.candidate.overlayId, 10);
  assert.equal(result.candidate.romOffset, null);
});

test("returns every overlapping static overlay candidate instead of guessing", async () => {
  const { map } = await buildResolverMap();
  const result = resolveRuntimeAddress(map, 0x02200090, "arm9");
  assert.equal(result.status, "ambiguous-runtime-address");
  if (result.status !== "ambiguous-runtime-address") assert.fail();
  assert.deepEqual(result.candidates.map((candidate) => candidate.overlayId), [10, 30]);
});

test("keeps processor address spaces separate", async () => {
  const { map } = await buildResolverMap();
  assert.equal(resolveRuntimeAddress(map, 0x02000040, "arm7").status, "unmapped");
});

test("returns unmapped for runtime addresses outside static candidates", async () => {
  const { map } = await buildResolverMap();
  assert.deepEqual(resolveRuntimeAddress(map, 0x023f0000, "arm9"), {
    status: "unmapped",
    address: 0x023f0000,
    processor: "arm9",
  });
});

test("classifies a ROM byte by every matching structural and runtime relationship", async () => {
  const { map } = await buildResolverMap();
  const result = resolveRomOffset(map, 0x1420);
  assert.equal(result.offset, 0x1420);
  assert.deepEqual(result.matches, [
    { kind: "nitrofs-file", fileId: 0, overlayId: null, runtimeAddress: null },
    { kind: "arm9-overlay", fileId: 0, overlayId: 10, runtimeAddress: 0x02200020 },
  ]);
});

test("does not invent runtime addresses for compressed overlay backing bytes", async () => {
  const { map } = await buildResolverMap();
  const result = resolveRomOffset(map, 0x1620);
  const overlay = result.matches.find((match) => match.kind === "arm9-overlay");
  assert.equal(overlay?.overlayId, 20);
  assert.equal(overlay?.runtimeAddress, null);
});

test("classifies structural header, FNT, FAT, and overlay-table regions", async () => {
  const { map } = await buildResolverMap();
  assert.equal(resolveRomOffset(map, 0x40).matches.some((match) => match.kind === "header"), true);
  assert.equal(resolveRomOffset(map, 0x900).matches.some((match) => match.kind === "fat"), true);
  assert.equal(resolveRomOffset(map, 0xa00).matches.some((match) => match.kind === "arm9-overlay-table"), true);
});

test("rejects ROM offsets outside the source file", async () => {
  const { map } = await buildResolverMap();
  assert.throws(
    () => resolveRomOffset(map, map.fileSize),
    (error: unknown) => error instanceof NdsError && error.category === "range-out-of-bounds",
  );
});
