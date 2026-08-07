import assert from "node:assert/strict";
import test from "node:test";

import { NdsError } from "../src/services/nds/errors.js";
import { parseNdsFat } from "../src/services/nds/fat.js";
import { parseNdsHeader } from "../src/services/nds/header.js";
import { parseNdsOverlays } from "../src/services/nds/overlays.js";
import {
  createNdsFixture,
  writeFatEntry,
  writeOverlayRecord,
} from "./helpers/nds-fixture.js";

async function parsedWithFat(fixture: Awaited<ReturnType<typeof createNdsFixture>>) {
  await fixture.write();
  const parsed = await parseNdsHeader(fixture.romPath);
  const fat = await parseNdsFat(parsed);
  return { parsed, fat };
}

test("parses ARM9 overlay metadata and compression flags", async () => {
  const fixture = await createNdsFixture({ fatSize: 32, arm9OverlaySize: 32 });
  writeFatEntry(fixture.buffer, 0x900, 0, 0x1000, 0x1010);
  writeFatEntry(fixture.buffer, 0x900, 1, 0x1100, 0x1120);
  writeFatEntry(fixture.buffer, 0x900, 2, 0x1200, 0x1230);
  writeFatEntry(fixture.buffer, 0x900, 3, 0x1400, 0x2400);
  writeOverlayRecord(fixture.buffer, 0xa00, 0, {
    overlayId: 37,
    ramAddress: 0x02210000,
    ramSize: 0x2000,
    bssSize: 0x200,
    staticInitStart: 0x02211f00,
    staticInitEnd: 0x02211f20,
    fileId: 3,
    compressedSize: 0x0f00,
    flags: 1,
  });

  const { parsed, fat } = await parsedWithFat(fixture);
  assert.deepEqual(await parseNdsOverlays(parsed, fat, "arm9"), [
    {
      processor: "arm9",
      overlayId: 37,
      ramAddress: 0x02210000,
      ramSize: 0x2000,
      ramEnd: 0x02212000,
      bssSize: 0x200,
      bssEnd: 0x02212200,
      staticInitStart: 0x02211f00,
      staticInitEnd: 0x02211f20,
      fileId: 3,
      romOffset: 0x1400,
      romSize: 0x1000,
      compressedSize: 0x0f00,
      flags: 1,
      compressed: true,
    },
  ]);
});

test("keeps ARM7 overlays processor-specific", async () => {
  const fixture = await createNdsFixture({ fatSize: 8, arm7OverlaySize: 32 });
  writeFatEntry(fixture.buffer, 0x900, 0, 0x1300, 0x1380);
  writeOverlayRecord(fixture.buffer, 0xb00, 0, {
    overlayId: 4,
    ramAddress: 0x03801000,
    ramSize: 0x80,
    bssSize: 0,
    staticInitStart: 0,
    staticInitEnd: 0,
    fileId: 0,
    compressedSize: 0,
    flags: 0,
  });
  const { parsed, fat } = await parsedWithFat(fixture);
  const overlays = await parseNdsOverlays(parsed, fat, "arm7");
  assert.equal(overlays[0]?.processor, "arm7");
  assert.equal(overlays[0]?.compressed, false);
  assert.equal(overlays[0]?.romSize, 0x80);
});

test("returns an empty list for an empty overlay table", async () => {
  const fixture = await createNdsFixture({ arm9OverlaySize: 0 });
  const { parsed, fat } = await parsedWithFat(fixture);
  assert.deepEqual(await parseNdsOverlays(parsed, fat, "arm9"), []);
});

test("rejects overlay table sizes not divisible by 32", async () => {
  const fixture = await createNdsFixture({ arm9OverlaySize: 31 });
  const { parsed, fat } = await parsedWithFat(fixture);
  await assert.rejects(
    parseNdsOverlays(parsed, fat, "arm9"),
    (error: unknown) => error instanceof NdsError && error.category === "malformed-overlay-table",
  );
});

test("rejects overlay file IDs outside the FAT", async () => {
  const fixture = await createNdsFixture({ fatSize: 8, arm9OverlaySize: 32 });
  writeFatEntry(fixture.buffer, 0x900, 0, 0x1000, 0x1100);
  writeOverlayRecord(fixture.buffer, 0xa00, 0, {
    overlayId: 1,
    ramAddress: 0x02200000,
    ramSize: 0x100,
    bssSize: 0,
    staticInitStart: 0,
    staticInitEnd: 0,
    fileId: 3,
    compressedSize: 0,
    flags: 0,
  });
  const { parsed, fat } = await parsedWithFat(fixture);
  await assert.rejects(
    parseNdsOverlays(parsed, fat, "arm9"),
    (error: unknown) => error instanceof NdsError && error.category === "malformed-overlay-table",
  );
});

test("rejects overlay runtime ranges that overflow 32-bit address space", async () => {
  const fixture = await createNdsFixture({ fatSize: 8, arm9OverlaySize: 32 });
  writeFatEntry(fixture.buffer, 0x900, 0, 0x1000, 0x1100);
  writeOverlayRecord(fixture.buffer, 0xa00, 0, {
    overlayId: 1,
    ramAddress: 0xfffffff0,
    ramSize: 0x20,
    bssSize: 0,
    staticInitStart: 0,
    staticInitEnd: 0,
    fileId: 0,
    compressedSize: 0,
    flags: 0,
  });
  const { parsed, fat } = await parsedWithFat(fixture);
  await assert.rejects(
    parseNdsOverlays(parsed, fat, "arm9"),
    (error: unknown) => error instanceof NdsError && error.category === "malformed-overlay-table",
  );
});

test("accepts zero static-init bounds but rejects inconsistent nonzero bounds", async () => {
  const valid = await createNdsFixture({ fatSize: 8, arm9OverlaySize: 32 });
  writeFatEntry(valid.buffer, 0x900, 0, 0x1000, 0x1100);
  writeOverlayRecord(valid.buffer, 0xa00, 0, {
    overlayId: 1,
    ramAddress: 0x02200000,
    ramSize: 0x100,
    bssSize: 0x40,
    staticInitStart: 0,
    staticInitEnd: 0,
    fileId: 0,
    compressedSize: 0,
    flags: 0,
  });
  const validParsed = await parsedWithFat(valid);
  assert.equal((await parseNdsOverlays(validParsed.parsed, validParsed.fat, "arm9"))[0]?.bssEnd, 0x02200140);

  const invalid = await createNdsFixture({ fatSize: 8, arm9OverlaySize: 32 });
  writeFatEntry(invalid.buffer, 0x900, 0, 0x1000, 0x1100);
  writeOverlayRecord(invalid.buffer, 0xa00, 0, {
    overlayId: 1,
    ramAddress: 0x02200000,
    ramSize: 0x100,
    bssSize: 0,
    staticInitStart: 0x02200080,
    staticInitEnd: 0x02200040,
    fileId: 0,
    compressedSize: 0,
    flags: 0,
  });
  const invalidParsed = await parsedWithFat(invalid);
  await assert.rejects(
    parseNdsOverlays(invalidParsed.parsed, invalidParsed.fat, "arm9"),
    (error: unknown) => error instanceof NdsError && error.category === "malformed-overlay-table",
  );
});

test("accepts overlapping overlay ranges and physical/runtime size differences", async () => {
  const fixture = await createNdsFixture({ fatSize: 16, arm9OverlaySize: 64 });
  writeFatEntry(fixture.buffer, 0x900, 0, 0x1000, 0x1080);
  writeFatEntry(fixture.buffer, 0x900, 1, 0x1100, 0x1180);
  writeOverlayRecord(fixture.buffer, 0xa00, 0, {
    overlayId: 12,
    ramAddress: 0x02200000,
    ramSize: 0x200,
    bssSize: 0x40,
    staticInitStart: 0,
    staticInitEnd: 0,
    fileId: 0,
    compressedSize: 0,
    flags: 0,
  });
  writeOverlayRecord(fixture.buffer, 0xa00, 1, {
    overlayId: 19,
    ramAddress: 0x02200000,
    ramSize: 0x180,
    bssSize: 0,
    staticInitStart: 0,
    staticInitEnd: 0,
    fileId: 1,
    compressedSize: 0,
    flags: 0,
  });
  const { parsed, fat } = await parsedWithFat(fixture);
  const overlays = await parseNdsOverlays(parsed, fat, "arm9");
  assert.equal(overlays.length, 2);
  assert.equal(overlays[0]?.romSize, 0x80);
  assert.equal(overlays[0]?.ramSize, 0x200);
  assert.equal(overlays[1]?.ramAddress, 0x02200000);
});
