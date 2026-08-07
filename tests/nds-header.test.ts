import assert from "node:assert/strict";
import test from "node:test";

import { NdsError } from "../src/services/nds/errors.js";
import {
  parseNdsHeader,
  readArm9HeaderMetadata,
} from "../src/services/nds/header.js";
import { createNdsFixture } from "./helpers/nds-fixture.js";

test("parses full NDS identity and executable metadata", async () => {
  const fixture = await createNdsFixture();
  const parsed = await parseNdsHeader(fixture.romPath);

  assert.equal(parsed.fileSize, fixture.buffer.length);
  assert.match(parsed.sha256, /^[a-f0-9]{64}$/);
  assert.equal(parsed.sha256Prefix, parsed.sha256.slice(0, 16));
  assert.equal(parsed.header.gameTitle, "RE-MCP TEST");
  assert.equal(parsed.header.gameCode, "TEST");
  assert.equal(parsed.header.makerCode, "01");
  assert.equal(parsed.header.arm9.romOffset, 0x200);
  assert.equal(parsed.header.arm9.ramAddress, 0x02000000);
  assert.equal(parsed.header.arm9.romEnd, 0x400);
  assert.equal(parsed.header.arm9.ramEnd, 0x02000200);
  assert.equal(parsed.header.arm7.romOffset, 0x600);
  assert.equal(parsed.header.arm7.ramAddress, 0x03800000);
  assert.equal(parsed.header.arm7.romEnd, 0x700);
  assert.equal(parsed.header.fnt.size, 0);
  assert.equal(parsed.header.fat.size, 0);
});

test("rejects a short NDS header", async () => {
  const fixture = await createNdsFixture({ fileSize: 0x20 });
  await assert.rejects(
    parseNdsHeader(fixture.romPath),
    (error: unknown) => error instanceof NdsError && error.category === "invalid-rom",
  );
});

test("rejects a directory instead of a regular ROM file", async () => {
  const fixture = await createNdsFixture();
  await assert.rejects(
    parseNdsHeader(fixture.directory),
    (error: unknown) => error instanceof NdsError && error.category === "invalid-rom",
  );
});

test("rejects zero ARM executable sizes in full parsing", async () => {
  await assert.rejects(
    parseNdsHeader((await createNdsFixture({ arm9Size: 0 })).romPath),
    (error: unknown) => error instanceof NdsError && error.category === "malformed-header",
  );
  await assert.rejects(
    parseNdsHeader((await createNdsFixture({ arm7Size: 0 })).romPath),
    (error: unknown) => error instanceof NdsError && error.category === "malformed-header",
  );
});

test("rejects executable runtime ranges that overflow 32-bit address space", async () => {
  await assert.rejects(
    parseNdsHeader((await createNdsFixture({ arm9RamAddress: 0xfffffff0, arm9Size: 0x100 })).romPath),
    (error: unknown) => error instanceof NdsError && error.category === "malformed-header",
  );
  await assert.rejects(
    parseNdsHeader((await createNdsFixture({ arm7RamAddress: 0xffffff80, arm7Size: 0x100 })).romPath),
    (error: unknown) => error instanceof NdsError && error.category === "malformed-header",
  );
});

test("rejects header-referenced regions beyond EOF", async () => {
  const fixture = await createNdsFixture({ fatOffset: 0x3ff0, fatSize: 0x100 });
  await assert.rejects(
    parseNdsHeader(fixture.romPath),
    (error: unknown) => error instanceof NdsError && error.category === "range-out-of-bounds",
  );
});

test("preserves empty optional table offsets without reading them", async () => {
  const fixture = await createNdsFixture({
    fntOffset: 0x1234,
    fntSize: 0,
    fatOffset: 0x1300,
    fatSize: 0,
    arm9OverlayOffset: 0x1400,
    arm9OverlaySize: 0,
    arm7OverlayOffset: 0x1500,
    arm7OverlaySize: 0,
  });
  const parsed = await parseNdsHeader(fixture.romPath);
  assert.deepEqual(parsed.header.fnt, { offset: 0x1234, size: 0, end: 0x1234 });
  assert.deepEqual(parsed.header.fat, { offset: 0x1300, size: 0, end: 0x1300 });
  assert.deepEqual(parsed.header.arm9OverlayTable, { offset: 0x1400, size: 0, end: 0x1400 });
  assert.deepEqual(parsed.header.arm7OverlayTable, { offset: 0x1500, size: 0, end: 0x1500 });
});

test("produces stable SHA-256 for identical ROM bytes", async () => {
  const first = await createNdsFixture();
  const second = await createNdsFixture();
  const a = await parseNdsHeader(first.romPath);
  const b = await parseNdsHeader(second.romPath);
  assert.equal(a.sha256, b.sha256);
});

test("ARM9 compatibility metadata ignores malformed unrelated FAT metadata", async () => {
  const fixture = await createNdsFixture({ fatOffset: 0x3ff0, fatSize: 0x100 });
  const arm9 = await readArm9HeaderMetadata(fixture.romPath);
  assert.equal(arm9.ramAddress, 0x02000000);
  assert.equal(arm9.size, 0x200);
  await assert.rejects(parseNdsHeader(fixture.romPath));
});
