import assert from "node:assert/strict";
import test from "node:test";

import { NdsError } from "../src/services/nds/errors.js";
import { parseNdsFat } from "../src/services/nds/fat.js";
import { parseNdsHeader } from "../src/services/nds/header.js";
import { createNdsFixture, writeFatEntry } from "./helpers/nds-fixture.js";

test("parses FAT entries by file ID", async () => {
  const fixture = await createNdsFixture({ fatSize: 16 });
  writeFatEntry(fixture.buffer, 0x900, 0, 0x1000, 0x1020);
  writeFatEntry(fixture.buffer, 0x900, 1, 0x1100, 0x1100);
  await fixture.write();

  const parsed = await parseNdsHeader(fixture.romPath);
  assert.deepEqual(await parseNdsFat(parsed), [
    { fileId: 0, startOffset: 0x1000, endOffset: 0x1020, size: 0x20 },
    { fileId: 1, startOffset: 0x1100, endOffset: 0x1100, size: 0 },
  ]);
});

test("returns an empty list for an empty FAT", async () => {
  const parsed = await parseNdsHeader((await createNdsFixture({ fatSize: 0 })).romPath);
  assert.deepEqual(await parseNdsFat(parsed), []);
});

test("rejects a FAT size that is not divisible by eight", async () => {
  const parsed = await parseNdsHeader((await createNdsFixture({ fatSize: 10 })).romPath);
  await assert.rejects(
    parseNdsFat(parsed),
    (error: unknown) => error instanceof NdsError && error.category === "malformed-fat",
  );
});

test("rejects FAT records whose start exceeds end", async () => {
  const fixture = await createNdsFixture({ fatSize: 8 });
  writeFatEntry(fixture.buffer, 0x900, 0, 0x1200, 0x1100);
  await fixture.write();
  const parsed = await parseNdsHeader(fixture.romPath);
  await assert.rejects(
    parseNdsFat(parsed),
    (error: unknown) => error instanceof NdsError && error.category === "malformed-fat",
  );
});

test("rejects FAT records that extend beyond the ROM", async () => {
  const fixture = await createNdsFixture({ fatSize: 8 });
  writeFatEntry(fixture.buffer, 0x900, 0, 0x3ff0, 0x4100);
  await fixture.write();
  const parsed = await parseNdsHeader(fixture.romPath);
  await assert.rejects(
    parseNdsFat(parsed),
    (error: unknown) => error instanceof NdsError && error.category === "range-out-of-bounds",
  );
});

test("accepts zero-length FAT files", async () => {
  const fixture = await createNdsFixture({ fatSize: 8 });
  writeFatEntry(fixture.buffer, 0x900, 0, 0x1200, 0x1200);
  await fixture.write();
  const parsed = await parseNdsHeader(fixture.romPath);
  assert.deepEqual(await parseNdsFat(parsed), [
    { fileId: 0, startOffset: 0x1200, endOffset: 0x1200, size: 0 },
  ]);
});
