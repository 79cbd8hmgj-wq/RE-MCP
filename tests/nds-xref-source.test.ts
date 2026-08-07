import assert from "node:assert/strict";
import test from "node:test";

import { NdsError } from "../src/services/nds/errors.js";
import {
  prepareNdsReferenceSearch,
  type ReferenceSearchScope,
} from "../src/services/nds/xref-source.js";
import { readNdsRomMap } from "../src/services/nds/rom-map.js";
import {
  createNdsFixture,
  writeFatEntry,
  writeOverlayRecord,
} from "./helpers/nds-fixture.js";

async function buildScopeFixture() {
  const fixture = await createNdsFixture({
    fileSize: 0x6000,
    fatSize: 24,
    arm9OverlaySize: 96,
  });
  const overlays = [
    { overlayId: 9, fileId: 0, rom: 0x1200, ram: 0x02220000, compressed: true },
    { overlayId: 3, fileId: 1, rom: 0x1300, ram: 0x02200000, compressed: false },
    { overlayId: 7, fileId: 2, rom: 0x1400, ram: 0x02210000, compressed: false },
  ] as const;
  for (const [index, overlay] of overlays.entries()) {
    writeFatEntry(fixture.buffer, 0x900, overlay.fileId, overlay.rom, overlay.rom + 0x80);
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
  return await readNdsRomMap(fixture.romPath);
}

function categoryOf(callback: () => unknown): string | null {
  try {
    callback();
    return null;
  } catch (error) {
    return error instanceof NdsError ? error.category : null;
  }
}

test("canonicalizes runtime and unique ROM-offset reverse-xref targets", async () => {
  const fixture = await createNdsFixture();
  const map = await readNdsRomMap(fixture.romPath);

  const runtime = prepareNdsReferenceSearch(
    map,
    "arm9",
    { targetRuntimeAddress: 0x02000008 },
    { kind: "main" },
    [],
  );
  assert.equal(runtime.target.requestedBy, "runtime-address");
  assert.equal(runtime.target.runtimeAddress, 0x02000008);
  assert.equal(runtime.target.romOffset, 0x208);
  assert.equal(runtime.target.resolution.status, "resolved");

  const rom = prepareNdsReferenceSearch(
    map,
    "arm9",
    { targetRomOffset: 0x208 },
    { kind: "main" },
    [],
  );
  assert.equal(rom.target.requestedBy, "rom-offset");
  assert.equal(rom.target.runtimeAddress, 0x02000008);
  assert.equal(rom.target.romOffset, 0x208);
  assert.equal(rom.target.resolution.status, "resolved");
});

test("rejects ambiguous and non-runtime-addressable ROM targets", async () => {
  const fixture = await createNdsFixture({
    fileSize: 0x5000,
    fatSize: 8,
    arm9OverlaySize: 32,
  });
  writeFatEntry(fixture.buffer, 0x900, 0, 0x200, 0x280);
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

  assert.equal(
    categoryOf(() => prepareNdsReferenceSearch(
      map,
      "arm9",
      { targetRomOffset: 0x208 },
      { kind: "main" },
      [],
    )),
    "ambiguous-reference-target",
  );

  assert.equal(
    categoryOf(() => prepareNdsReferenceSearch(
      map,
      "arm9",
      { targetRomOffset: 0x10 },
      { kind: "main" },
      [],
    )),
    "reference-target-not-runtime-addressable",
  );
});

test("expands scopes deterministically and preserves compression metadata", async () => {
  const map = await buildScopeFixture();
  const prepared = prepareNdsReferenceSearch(
    map,
    "arm9",
    { targetRuntimeAddress: 0x02000008 },
    { kind: "all-executable-components" },
    [],
  );

  assert.deepEqual(
    prepared.components.map((component) => [
      component.component,
      component.overlayId,
      component.compressed,
    ]),
    [
      ["main", null, false],
      ["overlay", 3, false],
      ["overlay", 7, false],
      ["overlay", 9, true],
    ],
  );

  const selected = prepareNdsReferenceSearch(
    map,
    "arm9",
    { targetRuntimeAddress: 0x02000008 },
    { kind: "main-and-overlays", overlayIds: [9, 3, 7] },
    [],
  );
  assert.deepEqual(
    selected.components.map((component) => [component.component, component.overlayId]),
    [["main", null], ["overlay", 3], ["overlay", 7], ["overlay", 9]],
  );
});

test("rejects empty, duplicate, and unknown overlay scopes", async () => {
  const map = await buildScopeFixture();
  const invalidScopes: readonly ReferenceSearchScope[] = [
    { kind: "overlay", overlayIds: [] },
    { kind: "main-and-overlays", overlayIds: [] },
    { kind: "overlay", overlayIds: [7, 7] },
    { kind: "overlay", overlayIds: [999] },
  ];

  for (const scope of invalidScopes) {
    assert.equal(
      categoryOf(() => prepareNdsReferenceSearch(
        map,
        "arm9",
        { targetRuntimeAddress: 0x02000008 },
        scope,
        [],
      )),
      "invalid-reference-scope",
    );
  }
});

test("validates explicit seeds against selected scope and deduplicates them", async () => {
  const map = await buildScopeFixture();
  const seed = {
    runtimeAddress: 0x02210000,
    mode: "thumb" as const,
    overlayId: 7,
  };
  const prepared = prepareNdsReferenceSearch(
    map,
    "arm9",
    { targetRuntimeAddress: 0x02000008 },
    { kind: "overlay", overlayIds: [7] },
    [seed, seed],
  );
  assert.equal(prepared.explicitSeeds.length, 1);
  assert.equal(prepared.explicitSeeds[0]?.component, "overlay");
  assert.equal(prepared.explicitSeeds[0]?.overlayId, 7);
  assert.equal(prepared.explicitSeeds[0]?.mode, "thumb");

  assert.equal(
    categoryOf(() => prepareNdsReferenceSearch(
      map,
      "arm9",
      { targetRuntimeAddress: 0x02000008 },
      { kind: "main" },
      [seed],
    )),
    "invalid-reference-seed",
  );

  assert.equal(
    categoryOf(() => prepareNdsReferenceSearch(
      map,
      "arm9",
      { targetRuntimeAddress: 0x02000008 },
      { kind: "overlay", overlayIds: [7] },
      [{ runtimeAddress: 0x02210000, mode: "thumb", overlayId: 3 }],
    )),
    "invalid-reference-seed",
  );
});
