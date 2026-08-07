import assert from "node:assert/strict";
import test from "node:test";

import { ownersForNdsPatternHit } from "../src/services/nds/pattern-ownership.js";
import { readNdsRomMap } from "../src/services/nds/rom-map.js";
import {
  createNdsFixture,
  encodeFntFileEntry,
  writeFatEntry,
  writeFntMainRecord,
  writeFntSubtable,
  writeOverlayRecord,
} from "./helpers/nds-fixture.js";

async function createOwnershipFixture() {
  const fixture = await createNdsFixture({
    fileSize: 0x5000,
    fntSize: 0x40,
    fatSize: 24,
    arm9OverlaySize: 64,
  });
  writeFatEntry(fixture.buffer, 0x900, 0, 0x1200, 0x1220);
  writeFatEntry(fixture.buffer, 0x900, 1, 0x1300, 0x1340);
  writeFatEntry(fixture.buffer, 0x900, 2, 0x1400, 0x1440);
  writeFntMainRecord(fixture.buffer, 0x800, 0, 8, 0, 1);
  writeFntSubtable(fixture.buffer, 0x800, 8, [encodeFntFileEntry("asset.bin")]);
  writeOverlayRecord(fixture.buffer, 0xa00, 0, {
    overlayId: 7,
    ramAddress: 0x02200000,
    ramSize: 0x20,
    bssSize: 0,
    staticInitStart: 0,
    staticInitEnd: 0,
    fileId: 1,
    compressedSize: 0,
    flags: 0,
  });
  writeOverlayRecord(fixture.buffer, 0xa00, 1, {
    overlayId: 8,
    ramAddress: 0x02300000,
    ramSize: 0x80,
    bssSize: 0,
    staticInitStart: 0,
    staticInitEnd: 0,
    fileId: 2,
    compressedSize: 0x30,
    flags: 1,
  });
  await fixture.write();
  return fixture;
}

test("maps full-span main executable hits to runtime addresses", async () => {
  const fixture = await createOwnershipFixture();
  const map = await readNdsRomMap(fixture.romPath);
  assert.deepEqual(ownersForNdsPatternHit(map, 0x204, 0x208), [{
    kind: "arm9-main",
    processor: "arm9",
    runtimeAddress: 0x02000004,
  }]);
});

test("maps only the directly file-backed uncompressed overlay prefix", async () => {
  const fixture = await createOwnershipFixture();
  const map = await readNdsRomMap(fixture.romPath);

  const mapped = ownersForNdsPatternHit(map, 0x1304, 0x1308)
    .find((owner) => owner.kind === "arm9-overlay");
  assert.equal(mapped?.runtimeAddress, 0x02200004);

  const beyondPrefix = ownersForNdsPatternHit(map, 0x1324, 0x1328)
    .find((owner) => owner.kind === "arm9-overlay");
  assert.equal(beyondPrefix?.runtimeAddress, null);
});

test("never fabricates runtime mapping for compressed overlay storage", async () => {
  const fixture = await createOwnershipFixture();
  const map = await readNdsRomMap(fixture.romPath);
  const owner = ownersForNdsPatternHit(map, 0x1404, 0x1408)
    .find((candidate) => candidate.kind === "arm9-overlay");
  assert.equal(owner?.runtimeAddress, null);
  assert.equal(owner?.compressed, true);
});

test("preserves multiple canonical owners for one physical hit", async () => {
  const fixture = await createOwnershipFixture();
  const map = await readNdsRomMap(fixture.romPath);
  const owners = ownersForNdsPatternHit(map, 0x1304, 0x1308);
  assert.equal(owners.some((owner) => owner.kind === "arm9-overlay"), true);
  const file = owners.find((owner) => owner.kind === "nitrofs-file");
  assert.equal(file?.fileId, 1);
});

test("reports validated structural ownership using full-span containment", async () => {
  const fixture = await createOwnershipFixture();
  const map = await readNdsRomMap(fixture.romPath);

  assert.deepEqual(ownersForNdsPatternHit(map, 0x10, 0x14), [{ kind: "header" }]);
  assert.deepEqual(ownersForNdsPatternHit(map, 0x808, 0x80c), [{ kind: "fnt" }]);
  assert.deepEqual(ownersForNdsPatternHit(map, 0x908, 0x90c), [{ kind: "fat" }]);
  assert.deepEqual(ownersForNdsPatternHit(map, 0xa00, 0xa04), [{ kind: "arm9-overlay-table" }]);

  assert.equal(
    ownersForNdsPatternHit(map, 0x900 + 22, 0x900 + 26)
      .some((owner) => owner.kind === "fat"),
    false,
  );
});

test("does not invent banner ownership from bannerOffset alone", async () => {
  const fixture = await createOwnershipFixture();
  const map = await readNdsRomMap(fixture.romPath);
  assert.deepEqual(ownersForNdsPatternHit(map, map.header.bannerOffset, map.header.bannerOffset + 4), [
    { kind: "unmapped" },
  ]);
});

test("uses unmapped only when no deterministic owner contains the full hit", async () => {
  const fixture = await createOwnershipFixture();
  const map = await readNdsRomMap(fixture.romPath);
  assert.deepEqual(ownersForNdsPatternHit(map, 0x1000, 0x1004), [{ kind: "unmapped" }]);
});
