import assert from "node:assert/strict";
import test from "node:test";

import { NdsError } from "../src/services/nds/errors.js";
import {
  canonicalizeFunctionTarget,
  prepareFunctionSearch,
} from "../src/services/nds/function-source.js";
import { readNdsRomMap } from "../src/services/nds/rom-map.js";
import {
  createNdsFixture,
  writeFatEntry,
  writeOverlayRecord,
} from "./helpers/nds-fixture.js";

async function buildFunctionSourceFixture() {
  const fixture = await createNdsFixture({
    fileSize: 0x6000,
    arm9Size: 0x80,
    fatSize: 32,
    arm9OverlaySize: 96,
  });

  writeFatEntry(fixture.buffer, 0x900, 0, 0x1200, 0x1280);
  writeFatEntry(fixture.buffer, 0x900, 1, 0x1300, 0x1380);
  writeFatEntry(fixture.buffer, 0x900, 2, 0x1400, 0x1480);
  writeFatEntry(fixture.buffer, 0x900, 3, 0x1500, 0x1540);

  writeOverlayRecord(fixture.buffer, 0xa00, 0, {
    overlayId: 7,
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
  writeOverlayRecord(fixture.buffer, 0xa00, 2, {
    overlayId: 11,
    ramAddress: 0x02300000,
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

function categoryOf(action: () => unknown): string | null {
  try {
    action();
    return null;
  } catch (error) {
    return error instanceof NdsError ? error.category : null;
  }
}

test("function search scope expands deterministically and marks compressed overlays", async () => {
  const { map } = await buildFunctionSourceFixture();

  const prepared = prepareFunctionSearch(
    map,
    "arm9",
    { kind: "main-and-overlays", overlayIds: [11, 9, 7] },
    [],
  );

  assert.deepEqual(prepared.components, [
    { processor: "arm9", component: "main", overlayId: null, compressed: false },
    { processor: "arm9", component: "overlay", overlayId: 7, compressed: false },
    { processor: "arm9", component: "overlay", overlayId: 9, compressed: true },
    { processor: "arm9", component: "overlay", overlayId: 11, compressed: false },
  ]);

  assert.equal(prepared.programEntry?.identity.runtimeAddress, 0x02000000);
  assert.equal(prepared.programEntry?.identity.romOffset, 0x200);
  assert.equal(prepared.programEntry?.identity.mode, "arm");
  assert.equal(prepared.programEntry?.proof.kind, "program-entry");
});

test("overlay-only function scope has no synthetic program-entry proof", async () => {
  const { map } = await buildFunctionSourceFixture();
  const prepared = prepareFunctionSearch(
    map,
    "arm9",
    { kind: "overlay", overlayIds: [7] },
    [{ runtimeAddress: 0x02200000, mode: "thumb", overlayId: 7 }],
  );

  assert.equal(prepared.programEntry, null);
  assert.equal(prepared.explicitSeeds.length, 1);
  assert.equal(prepared.explicitSeeds[0]?.overlayId, 7);
  assert.equal(prepared.explicitSeeds[0]?.mode, "thumb");
});

test("function search deduplicates canonical explicit seeds without proving them", async () => {
  const { map } = await buildFunctionSourceFixture();
  const prepared = prepareFunctionSearch(
    map,
    "arm9",
    { kind: "overlay", overlayIds: [7] },
    [
      { runtimeAddress: 0x02200000, mode: "arm", overlayId: 7 },
      { runtimeAddress: 0x02200000, mode: "arm", overlayId: 7 },
    ],
  );

  assert.equal(prepared.explicitSeeds.length, 1);
  assert.equal(prepared.programEntry, null);
});

test("function search rejects duplicate and unknown overlay scope selectors", async () => {
  const { map } = await buildFunctionSourceFixture();

  assert.equal(
    categoryOf(() => prepareFunctionSearch(
      map,
      "arm9",
      { kind: "overlay", overlayIds: [7, 7] },
      [],
    )),
    "invalid-function-scope",
  );

  assert.equal(
    categoryOf(() => prepareFunctionSearch(
      map,
      "arm9",
      { kind: "overlay", overlayIds: [99] },
      [],
    )),
    "invalid-function-scope",
  );
});

test("function search rejects invalid coverage seeds conservatively", async () => {
  const { map } = await buildFunctionSourceFixture();

  assert.equal(
    categoryOf(() => prepareFunctionSearch(
      map,
      "arm9",
      { kind: "overlay", overlayIds: [7] },
      [{ runtimeAddress: 0x02200001, mode: "thumb", overlayId: 7 }],
    )),
    "invalid-function-seed",
  );

  assert.equal(
    categoryOf(() => prepareFunctionSearch(
      map,
      "arm9",
      { kind: "main" },
      [{ runtimeAddress: 0x02200000, mode: "arm", overlayId: 7 }],
    )),
    "invalid-function-seed",
  );

  assert.equal(
    categoryOf(() => prepareFunctionSearch(
      map,
      "arm9",
      { kind: "overlay", overlayIds: [9] },
      [{ runtimeAddress: 0x02210000, mode: "arm", overlayId: 9 }],
    )),
    "invalid-function-seed",
  );

  assert.equal(
    categoryOf(() => prepareFunctionSearch(
      map,
      "arm9",
      { kind: "overlay", overlayIds: [7] },
      [{ runtimeAddress: 0x02200080, mode: "arm", overlayId: 7 }],
    )),
    "invalid-function-seed",
  );
});

test("canonical function target requires exact selected uncompressed file-backed ownership", async () => {
  const { map } = await buildFunctionSourceFixture();
  const selected = new Set(["arm9:main", "arm9:overlay:7"]);

  assert.deepEqual(
    canonicalizeFunctionTarget(map, "arm9", 0x02000010, "arm", selected),
    {
      processor: "arm9",
      component: "main",
      overlayId: null,
      runtimeAddress: 0x02000010,
      romOffset: 0x210,
      mode: "arm",
    },
  );

  assert.deepEqual(
    canonicalizeFunctionTarget(map, "arm9", 0x02200000, "thumb", selected),
    {
      processor: "arm9",
      component: "overlay",
      overlayId: 7,
      runtimeAddress: 0x02200000,
      romOffset: 0x1200,
      mode: "thumb",
    },
  );

  assert.equal(
    canonicalizeFunctionTarget(map, "arm9", 0x02210000, "arm", selected),
    null,
  );
  assert.equal(
    canonicalizeFunctionTarget(map, "arm9", 0x02300000, "arm", selected),
    null,
  );
  assert.equal(
    canonicalizeFunctionTarget(map, "arm9", 0x03000000, "arm", selected),
    null,
  );
});

test("canonical function target preserves overlay ambiguity instead of selecting by scope", async () => {
  const fixture = await createNdsFixture({
    fileSize: 0x5000,
    fatSize: 16,
    arm9OverlaySize: 64,
  });
  writeFatEntry(fixture.buffer, 0x900, 0, 0x1200, 0x1280);
  writeFatEntry(fixture.buffer, 0x900, 1, 0x1300, 0x1380);
  for (const [index, overlayId, fileId] of [
    [0, 7, 0],
    [1, 8, 1],
  ] as const) {
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

  assert.equal(
    canonicalizeFunctionTarget(
      map,
      "arm9",
      0x02200000,
      "arm",
      new Set(["arm9:overlay:7"]),
    ),
    null,
  );
});
