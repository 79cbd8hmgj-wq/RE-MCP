import assert from "node:assert/strict";
import test from "node:test";

import { resolveNdsCodeSource } from "../src/services/nds/disassembly-source.js";
import { readNdsRomMap } from "../src/services/nds/rom-map.js";
import {
  createNdsFixture,
  writeFatEntry,
  writeOverlayRecord,
} from "./helpers/nds-fixture.js";

async function createCompressedOverlayMap() {
  const fixture = await createNdsFixture({
    fileSize: 0x5000,
    fatSize: 8,
    arm9OverlaySize: 32,
  });
  writeFatEntry(fixture.buffer, 0x900, 0, 0x1200, 0x1280);
  writeOverlayRecord(fixture.buffer, 0xa00, 0, {
    overlayId: 7,
    ramAddress: 0x02200000,
    ramSize: 0x100,
    bssSize: 0x20,
    staticInitStart: 0,
    staticInitEnd: 0,
    fileId: 0,
    compressedSize: 0x70,
    flags: 1,
  });
  await fixture.write();
  return await readNdsRomMap(fixture.romPath);
}

test("explicit compressed overlay runtime source resolves as derived code without fabricated ROM provenance", async () => {
  const map = await createCompressedOverlayMap();
  const result = resolveNdsCodeSource(map, {
    processor: "arm9",
    runtimeAddress: 0x02200010,
    overlayId: 7,
    mode: "arm",
  });

  assert.equal(result.status, "resolved");
  if (result.status !== "resolved") return;

  assert.equal(result.source.component, "overlay");
  assert.equal(result.source.overlayId, 7);
  assert.equal(result.source.runtimeAddress, 0x02200010);
  assert.equal(result.source.runtimeStart, 0x02200000);
  assert.equal(result.source.runtimeEnd, 0x02200100);
  assert.equal(result.source.representation, "derived-overlay");
  assert.equal(result.source.romOffset, null);
  assert.equal(result.source.runtimeImageOffset, 0x10);
  assert.equal(result.source.romStart, null);
  assert.equal(result.source.romEnd, null);
});

test("compressed overlay physical storage never resolves as decoded runtime code", async () => {
  const map = await createCompressedOverlayMap();
  const result = resolveNdsCodeSource(map, {
    processor: "arm9",
    romOffset: 0x1210,
    overlayId: 7,
    mode: "arm",
  });

  assert.equal(result.status, "unmapped-address");
});
