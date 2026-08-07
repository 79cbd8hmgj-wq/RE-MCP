import assert from "node:assert/strict";
import test from "node:test";

import { NdsError } from "../src/services/nds/errors.js";
import { parseNdsFat } from "../src/services/nds/fat.js";
import { parseNdsFnt } from "../src/services/nds/fnt.js";
import { parseNdsHeader } from "../src/services/nds/header.js";
import {
  createNdsFixture,
  encodeFntDirectoryEntry,
  encodeFntFileEntry,
  writeFatEntry,
  writeFntMainRecord,
  writeFntSubtable,
} from "./helpers/nds-fixture.js";

async function parseFixtureFilesystem(fixture: Awaited<ReturnType<typeof createNdsFixture>>) {
  await fixture.write();
  const parsed = await parseNdsHeader(fixture.romPath);
  const fat = await parseNdsFat(parsed);
  return await parseNdsFnt(parsed, fat);
}

test("reconstructs nested NitroFS paths and preserves unnamed FAT entries", async () => {
  const fixture = await createNdsFixture({ fntSize: 0x80, fatSize: 24 });
  writeFatEntry(fixture.buffer, 0x900, 0, 0x1000, 0x1010);
  writeFatEntry(fixture.buffer, 0x900, 1, 0x1100, 0x1120);
  writeFatEntry(fixture.buffer, 0x900, 2, 0x1200, 0x1230);

  const rootSubtableOffset = 16;
  const childSubtableOffset = writeFntSubtable(fixture.buffer, 0x800, rootSubtableOffset, [
    encodeFntFileEntry("root.bin"),
    encodeFntDirectoryEntry("data", 0xf001),
  ]);
  writeFntSubtable(fixture.buffer, 0x800, childSubtableOffset, [
    encodeFntFileEntry("nested.bin"),
  ]);
  writeFntMainRecord(fixture.buffer, 0x800, 0, rootSubtableOffset, 0, 2);
  writeFntMainRecord(fixture.buffer, 0x800, 1, childSubtableOffset, 1, 0xf000);

  const filesystem = await parseFixtureFilesystem(fixture);
  assert.deepEqual(filesystem.directories, [
    { directoryId: 0xf000, parentDirectoryId: null, path: "", firstFileId: 0 },
    { directoryId: 0xf001, parentDirectoryId: 0xf000, path: "data", firstFileId: 1 },
  ]);
  assert.equal(filesystem.files[0]?.path, "root.bin");
  assert.equal(filesystem.files[1]?.path, "data/nested.bin");
  assert.equal(filesystem.files[2]?.path, null);
});

test("returns unnamed FAT entries when the FNT is empty", async () => {
  const fixture = await createNdsFixture({ fntSize: 0, fatSize: 8 });
  writeFatEntry(fixture.buffer, 0x900, 0, 0x1000, 0x1010);
  const filesystem = await parseFixtureFilesystem(fixture);
  assert.deepEqual(filesystem.directories, []);
  assert.equal(filesystem.files[0]?.path, null);
});

test("rejects a child directory ID outside the root directory count", async () => {
  const fixture = await createNdsFixture({ fntSize: 0x40 });
  writeFntMainRecord(fixture.buffer, 0x800, 0, 8, 0, 1);
  writeFntSubtable(fixture.buffer, 0x800, 8, [
    encodeFntDirectoryEntry("bad", 0xf001),
  ]);
  await assert.rejects(
    parseFixtureFilesystem(fixture),
    (error: unknown) => error instanceof NdsError && error.category === "malformed-fnt",
  );
});

test("rejects directory cycles", async () => {
  const fixture = await createNdsFixture({ fntSize: 0x60 });
  const rootSubtableOffset = 16;
  const childSubtableOffset = writeFntSubtable(fixture.buffer, 0x800, rootSubtableOffset, [
    encodeFntDirectoryEntry("child", 0xf001),
  ]);
  writeFntSubtable(fixture.buffer, 0x800, childSubtableOffset, [
    encodeFntDirectoryEntry("back", 0xf000),
  ]);
  writeFntMainRecord(fixture.buffer, 0x800, 0, rootSubtableOffset, 0, 2);
  writeFntMainRecord(fixture.buffer, 0x800, 1, childSubtableOffset, 0, 0xf000);
  await assert.rejects(
    parseFixtureFilesystem(fixture),
    (error: unknown) => error instanceof NdsError && error.category === "malformed-fnt",
  );
});

test("rejects a directory subtable offset outside the FNT", async () => {
  const fixture = await createNdsFixture({ fntSize: 0x20 });
  writeFntMainRecord(fixture.buffer, 0x800, 0, 0x100, 0, 1);
  await assert.rejects(
    parseFixtureFilesystem(fixture),
    (error: unknown) => error instanceof NdsError && error.category === "malformed-fnt",
  );
});

test("rejects file IDs outside the FAT", async () => {
  const fixture = await createNdsFixture({ fntSize: 0x30, fatSize: 8 });
  writeFatEntry(fixture.buffer, 0x900, 0, 0x1000, 0x1010);
  writeFntMainRecord(fixture.buffer, 0x800, 0, 8, 1, 1);
  writeFntSubtable(fixture.buffer, 0x800, 8, [encodeFntFileEntry("bad.bin")]);
  await assert.rejects(
    parseFixtureFilesystem(fixture),
    (error: unknown) => error instanceof NdsError && error.category === "malformed-fnt",
  );
});

test("rejects an unterminated directory subtable", async () => {
  const fixture = await createNdsFixture({ fntSize: 12, fatSize: 8 });
  writeFatEntry(fixture.buffer, 0x900, 0, 0x1000, 0x1010);
  writeFntMainRecord(fixture.buffer, 0x800, 0, 8, 0, 1);
  const entry = encodeFntFileEntry("abc");
  entry.copy(fixture.buffer, 0x808);
  await assert.rejects(
    parseFixtureFilesystem(fixture),
    (error: unknown) => error instanceof NdsError && error.category === "malformed-fnt",
  );
});

test("preserves unusual single-byte filename values without corrupting traversal", async () => {
  const fixture = await createNdsFixture({ fntSize: 0x30, fatSize: 8 });
  writeFatEntry(fixture.buffer, 0x900, 0, 0x1000, 0x1010);
  writeFntMainRecord(fixture.buffer, 0x800, 0, 8, 0, 1);
  writeFntSubtable(fixture.buffer, 0x800, 8, [encodeFntFileEntry("\x80.bin")]);
  const filesystem = await parseFixtureFilesystem(fixture);
  assert.equal(filesystem.files[0]?.path, "\x80.bin");
});
