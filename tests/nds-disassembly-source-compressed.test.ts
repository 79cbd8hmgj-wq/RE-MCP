import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  resolveNdsCodeSource,
  withValidatedNdsCodeReader,
} from "../src/services/nds/disassembly-source.js";
import { readNdsRomMap } from "../src/services/nds/rom-map.js";
import {
  createNdsFixture,
  writeFatEntry,
  writeOverlayRecord,
} from "./helpers/nds-fixture.js";

async function createCompressedOverlayMap() {
  const stored = await readFile("tests/fixtures/nds-blz/uncompressed-prefix.bin");
  const decoded = await readFile("tests/fixtures/nds-blz/uncompressed-prefix.dec.bin");
  const backingSize = stored.length + 8;
  const fixture = await createNdsFixture({
    fileSize: 0x5000,
    fatSize: 8,
    arm9OverlaySize: 32,
  });
  writeFatEntry(fixture.buffer, 0x900, 0, 0x1200, 0x1200 + backingSize);
  stored.copy(fixture.buffer, 0x1200);
  Buffer.from("TRAILING").copy(fixture.buffer, 0x1200 + stored.length);
  writeOverlayRecord(fixture.buffer, 0xa00, 0, {
    overlayId: 7,
    ramAddress: 0x02200000,
    ramSize: decoded.length,
    bssSize: 0x20,
    staticInitStart: 0,
    staticInitEnd: 0,
    fileId: 0,
    compressedSize: stored.length,
    flags: 1,
  });
  await fixture.write();
  return {
    map: await readNdsRomMap(fixture.romPath),
    decoded,
  };
}

test("explicit compressed overlay runtime source resolves as derived code without fabricated ROM provenance", async () => {
  const { map } = await createCompressedOverlayMap();
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
  assert.equal(result.source.runtimeEnd, 0x02200000 + (await createCompressedOverlayMap()).decoded.length);
  assert.equal(result.source.representation, "derived-overlay");
  assert.equal(result.source.romOffset, null);
  assert.equal(result.source.runtimeImageOffset, 0x10);
  assert.equal(result.source.romStart, null);
  assert.equal(result.source.romEnd, null);
});

test("validated NDS code reader returns exact decoded runtime bytes for compressed overlays", async () => {
  const { map, decoded } = await createCompressedOverlayMap();
  const result = resolveNdsCodeSource(map, {
    processor: "arm9",
    runtimeAddress: 0x02200010,
    overlayId: 7,
    mode: "arm",
  });
  assert.equal(result.status, "resolved");
  if (result.status !== "resolved") return;

  const bytes = await withValidatedNdsCodeReader(map, (read) => read(result.source, 12));
  assert.deepEqual(bytes, decoded.subarray(0x10, 0x1c));
});

test("compressed overlay physical storage never resolves as decoded runtime code", async () => {
  const { map } = await createCompressedOverlayMap();
  const result = resolveNdsCodeSource(map, {
    processor: "arm9",
    romOffset: 0x1210,
    overlayId: 7,
    mode: "arm",
  });

  assert.equal(result.status, "unmapped-address");
});
