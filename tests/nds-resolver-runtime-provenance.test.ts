import assert from "node:assert/strict";
import test from "node:test";

import { resolveRomOffset, resolveRuntimeAddress } from "../src/services/nds/resolver.js";
import { readNdsRomMap } from "../src/services/nds/rom-map.js";
import {
  createNdsFixture,
  writeFatEntry,
  writeOverlayRecord,
} from "./helpers/nds-fixture.js";

async function provenanceMap() {
  const fixture = await createNdsFixture({
    fileSize: 0x5000,
    fatSize: 16,
    arm9OverlaySize: 64,
  });
  writeFatEntry(fixture.buffer, 0x900, 0, 0x1400, 0x1480);
  writeFatEntry(fixture.buffer, 0x900, 1, 0x1600, 0x1680);
  writeOverlayRecord(fixture.buffer, 0xa00, 0, {
    overlayId: 10,
    ramAddress: 0x02200000,
    ramSize: 0x80,
    bssSize: 0x20,
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
  await fixture.write();
  return readNdsRomMap(fixture.romPath);
}

test("main initialized runtime bytes expose ROM-backed runtime-image provenance", async () => {
  const map = await provenanceMap();
  const result = resolveRuntimeAddress(map, 0x02000040, "arm9");
  assert.equal(result.status, "resolved");
  if (result.status !== "resolved") assert.fail();

  assert.equal(result.candidate.romOffset, 0x240);
  assert.equal(result.candidate.runtimeImageOffset, 0x40);
  assert.equal(result.candidate.representation, "rom-file-backed");
});

test("uncompressed overlay initialized bytes expose ROM-backed runtime-image provenance", async () => {
  const map = await provenanceMap();
  const result = resolveRuntimeAddress(map, 0x02200024, "arm9");
  assert.equal(result.status, "resolved");
  if (result.status !== "resolved") assert.fail();

  assert.equal(result.candidate.overlayId, 10);
  assert.equal(result.candidate.romOffset, 0x1424);
  assert.equal(result.candidate.runtimeImageOffset, 0x24);
  assert.equal(result.candidate.representation, "rom-file-backed");
});

test("compressed overlay runtime bytes expose derived provenance without a fabricated ROM offset", async () => {
  const map = await provenanceMap();
  const result = resolveRuntimeAddress(map, 0x02210040, "arm9");
  assert.equal(result.status, "compressed-no-direct-rom-mapping");
  if (result.status !== "compressed-no-direct-rom-mapping") assert.fail();

  assert.equal(result.candidate.overlayId, 20);
  assert.equal(result.candidate.romOffset, null);
  assert.equal(result.candidate.runtimeImageOffset, 0x40);
  assert.equal(result.candidate.representation, "derived-overlay");
  assert.equal(result.candidate.backingRomOffset, 0x1600);
  assert.equal(result.candidate.backingRomSize, 0x80);
});

test("overlay BSS remains runtime-only with no initialized-image offset", async () => {
  const map = await provenanceMap();
  const result = resolveRuntimeAddress(map, 0x02200090, "arm9");
  assert.equal(result.status, "runtime-only-bss");
  if (result.status !== "runtime-only-bss") assert.fail();

  assert.equal(result.candidate.overlayId, 10);
  assert.equal(result.candidate.romOffset, null);
  assert.equal(result.candidate.runtimeImageOffset, null);
  assert.equal(result.candidate.representation, "runtime-only");
});

test("physical compressed overlay storage still has no decoded runtime mapping", async () => {
  const map = await provenanceMap();
  const result = resolveRomOffset(map, 0x1620);
  const overlay = result.matches.find((match) => match.kind === "arm9-overlay");

  assert.equal(overlay?.overlayId, 20);
  assert.equal(overlay?.runtimeAddress, null);
});
