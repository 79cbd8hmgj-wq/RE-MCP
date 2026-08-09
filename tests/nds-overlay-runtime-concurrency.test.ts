import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { NdsError } from "../src/services/nds/errors.js";
import { createNdsOverlayRuntimeContext } from "../src/services/nds/overlay-runtime.js";
import { readNdsRomMap } from "../src/services/nds/rom-map.js";
import {
  createNdsFixture,
  writeFatEntry,
  writeOverlayRecord,
} from "./helpers/nds-fixture.js";

const BLZ_ROOT = fileURLToPath(new URL("./fixtures/nds-blz/", import.meta.url));

async function mapWithTwoCompressedOverlays() {
  const [compressed, decoded] = await Promise.all([
    readFile(path.join(BLZ_ROOT, "backreference.bin")),
    readFile(path.join(BLZ_ROOT, "backreference.dec.bin")),
  ]);
  const fixture = await createNdsFixture({
    fileSize: 0x4000,
    fatSize: 16,
    arm9OverlaySize: 32,
    arm7OverlaySize: 32,
  });
  writeFatEntry(fixture.buffer, 0x900, 0, 0x1400, 0x1400 + compressed.length);
  writeFatEntry(fixture.buffer, 0x900, 1, 0x1600, 0x1600 + compressed.length);
  writeOverlayRecord(fixture.buffer, 0xa00, 0, {
    overlayId: 7,
    ramAddress: 0x02200000,
    ramSize: decoded.length,
    bssSize: 0,
    staticInitStart: 0,
    staticInitEnd: 0,
    fileId: 0,
    compressedSize: compressed.length,
    flags: 1,
  });
  writeOverlayRecord(fixture.buffer, 0xb00, 0, {
    overlayId: 11,
    ramAddress: 0x03801000,
    ramSize: decoded.length,
    bssSize: 0,
    staticInitStart: 0,
    staticInitEnd: 0,
    fileId: 1,
    compressedSize: compressed.length,
    flags: 1,
  });
  compressed.copy(fixture.buffer, 0x1400);
  compressed.copy(fixture.buffer, 0x1600);
  await fixture.write();
  return { map: await readNdsRomMap(fixture.romPath), decodedSize: decoded.length };
}

test("concurrent unique overlay decodes cannot race past the aggregate budget", async () => {
  const { map, decodedSize } = await mapWithTwoCompressedOverlays();
  const context = createNdsOverlayRuntimeContext(map, {
    maxAggregateDecodedBytes: decodedSize * 2 - 1,
  });

  const results = await Promise.allSettled([
    context.getCompressedOverlay("arm9", 7),
    context.getCompressedOverlay("arm7", 11),
  ]);
  const fulfilled = results.filter((result) => result.status === "fulfilled");
  const rejected = results.filter((result) => result.status === "rejected");

  assert.equal(fulfilled.length, 1);
  assert.equal(rejected.length, 1);
  assert.ok(rejected[0]!.reason instanceof NdsError);
  assert.equal(rejected[0]!.reason.category, "blz-output-limit");
  assert.equal(context.decodedBytesCharged, decodedSize);
});
