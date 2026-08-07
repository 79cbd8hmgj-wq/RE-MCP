import assert from "node:assert/strict";
import test from "node:test";

import { readNdsRomMap } from "../src/services/nds/rom-map.js";
import {
  createNdsFixture,
  writeFatEntry,
  writeOverlayRecord,
} from "./helpers/nds-fixture.js";

test("composes one canonical ROM identity with FAT, filesystem, overlays, and ranges", async () => {
  const fixture = await createNdsFixture({
    fatSize: 16,
    arm9OverlaySize: 32,
    arm7OverlaySize: 32,
  });
  writeFatEntry(fixture.buffer, 0x900, 0, 0x1000, 0x1080);
  writeFatEntry(fixture.buffer, 0x900, 1, 0x1100, 0x1180);
  writeOverlayRecord(fixture.buffer, 0xa00, 0, {
    overlayId: 10,
    ramAddress: 0x02200000,
    ramSize: 0x100,
    bssSize: 0x20,
    staticInitStart: 0,
    staticInitEnd: 0,
    fileId: 0,
    compressedSize: 0,
    flags: 0,
  });
  writeOverlayRecord(fixture.buffer, 0xb00, 0, {
    overlayId: 2,
    ramAddress: 0x03802000,
    ramSize: 0x80,
    bssSize: 0,
    staticInitStart: 0,
    staticInitEnd: 0,
    fileId: 1,
    compressedSize: 0x70,
    flags: 1,
  });
  await fixture.write();

  const map = await readNdsRomMap(fixture.romPath);
  assert.equal(map.romPath, fixture.romPath);
  assert.equal(map.fileSize, fixture.buffer.length);
  assert.match(map.sha256, /^[a-f0-9]{64}$/);
  assert.equal(map.sha256Prefix, map.sha256.slice(0, 16));
  assert.equal(map.fat.length, 2);
  assert.equal(map.filesystem.files.length, 2);
  assert.equal(map.filesystem.files[0]?.path, null);
  assert.equal(map.overlays.arm9[0]?.overlayId, 10);
  assert.equal(map.overlays.arm7[0]?.overlayId, 2);
  assert.equal(map.overlays.arm7[0]?.compressed, true);

  assert.deepEqual(map.executableRanges, [
    {
      kind: "arm9-main",
      processor: "arm9",
      start: 0x02000000,
      initializedEnd: 0x02000200,
      end: 0x02000200,
      sourceId: "arm9-main",
      overlayId: null,
      compressed: false,
    },
    {
      kind: "arm7-main",
      processor: "arm7",
      start: 0x03800000,
      initializedEnd: 0x03800100,
      end: 0x03800100,
      sourceId: "arm7-main",
      overlayId: null,
      compressed: false,
    },
    {
      kind: "arm9-overlay",
      processor: "arm9",
      start: 0x02200000,
      initializedEnd: 0x02200100,
      end: 0x02200120,
      sourceId: "arm9-overlay:10",
      overlayId: 10,
      compressed: false,
    },
    {
      kind: "arm7-overlay",
      processor: "arm7",
      start: 0x03802000,
      initializedEnd: 0x03802080,
      end: 0x03802080,
      sourceId: "arm7-overlay:2",
      overlayId: 2,
      compressed: true,
    },
  ]);
});

test("sorts overlay executable ranges deterministically by processor and overlay ID", async () => {
  const fixture = await createNdsFixture({ fatSize: 16, arm9OverlaySize: 64 });
  writeFatEntry(fixture.buffer, 0x900, 0, 0x1000, 0x1080);
  writeFatEntry(fixture.buffer, 0x900, 1, 0x1100, 0x1180);
  writeOverlayRecord(fixture.buffer, 0xa00, 0, {
    overlayId: 19,
    ramAddress: 0x02210000,
    ramSize: 0x80,
    bssSize: 0,
    staticInitStart: 0,
    staticInitEnd: 0,
    fileId: 0,
    compressedSize: 0,
    flags: 0,
  });
  writeOverlayRecord(fixture.buffer, 0xa00, 1, {
    overlayId: 12,
    ramAddress: 0x02200000,
    ramSize: 0x80,
    bssSize: 0,
    staticInitStart: 0,
    staticInitEnd: 0,
    fileId: 1,
    compressedSize: 0,
    flags: 0,
  });
  await fixture.write();

  const map = await readNdsRomMap(fixture.romPath);
  assert.deepEqual(
    map.executableRanges.slice(2).map((range) => range.overlayId),
    [12, 19],
  );
});

test("composes an empty filesystem and overlay set without inventing entries", async () => {
  const fixture = await createNdsFixture();
  const map = await readNdsRomMap(fixture.romPath);
  assert.deepEqual(map.fat, []);
  assert.deepEqual(map.filesystem.directories, []);
  assert.deepEqual(map.filesystem.files, []);
  assert.deepEqual(map.overlays, { arm9: [], arm7: [] });
  assert.equal(map.executableRanges.length, 2);
});
