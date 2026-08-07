import assert from "node:assert/strict";
import test from "node:test";

import { NdsError } from "../src/services/nds/errors.js";
import { searchNdsPattern } from "../src/services/nds/pattern-search.js";
import { readNdsRomMap } from "../src/services/nds/rom-map.js";
import {
  createNdsFixture,
  encodeFntFileEntry,
  writeFatEntry,
  writeFntMainRecord,
  writeFntSubtable,
  writeOverlayRecord,
} from "./helpers/nds-fixture.js";

async function createSearchFixture() {
  const fixture = await createNdsFixture({
    fileSize: 0x5000,
    arm9Size: 0x40,
    fntSize: 0x40,
    fatSize: 24,
    arm9OverlaySize: 32,
  });

  writeFatEntry(fixture.buffer, 0x900, 0, 0x1200, 0x1220);
  writeFatEntry(fixture.buffer, 0x900, 1, 0x1220, 0x1240);
  writeFatEntry(fixture.buffer, 0x900, 2, 0x1300, 0x1340);
  writeFntMainRecord(fixture.buffer, 0x800, 0, 8, 0, 1);
  writeFntSubtable(fixture.buffer, 0x800, 8, [
    encodeFntFileEntry("first.bin"),
    encodeFntFileEntry("second.bin"),
    encodeFntFileEntry("overlay.bin"),
  ]);

  writeOverlayRecord(fixture.buffer, 0xa00, 0, {
    overlayId: 7,
    ramAddress: 0x02200000,
    ramSize: 0x80,
    bssSize: 0,
    staticInitStart: 0,
    staticInitEnd: 0,
    fileId: 2,
    compressedSize: 0x30,
    flags: 1,
  });

  fixture.buffer.set([0xaa, 0xaa, 0xaa], 0x200);
  fixture.buffer.writeUInt32LE(0x12345678, 0x210);
  Buffer.from("HELLO", "ascii").copy(fixture.buffer, 0x220);
  Buffer.from("AΩ", "utf16le").copy(fixture.buffer, 0x230);
  fixture.buffer.fill(0x00, 0x1200, 0x1240);
  fixture.buffer[0x1200] = 0x11;
  fixture.buffer[0x1201] = 0xaa;
  fixture.buffer[0x1202] = 0xbb;
  fixture.buffer[0x121f] = 0xcc;
  fixture.buffer[0x1220] = 0xdd;
  fixture.buffer[0x123f] = 0xee;
  fixture.buffer.fill(0x77, 0x1300, 0x1340);
  fixture.buffer.set([0xde, 0xad, 0xbe, 0xef], 0x1304);
  await fixture.write();
  return fixture;
}

test("searches ARM9 main and returns canonical overlapping hit records", async () => {
  const fixture = await createSearchFixture();
  const map = await readNdsRomMap(fixture.romPath);
  const result = await searchNdsPattern(
    map,
    { kind: "byte-signature", signature: "AA AA" },
    { kind: "components", arm9Main: true },
    { limit: 10 },
  );

  assert.equal(result.status, "complete");
  assert.deepEqual(result.matches.map((hit) => hit.romOffset), [0x200, 0x201]);
  assert.deepEqual(result.matches.map((hit) => hit.bytesHex), ["aaaa", "aaaa"]);
  assert.deepEqual(result.matches[0]?.owners, [{
    kind: "arm9-main",
    processor: "arm9",
    runtimeAddress: 0x02000000,
  }]);
});

test("supports integer, ASCII, and UTF-16LE patterns through the same service", async () => {
  const fixture = await createSearchFixture();
  const map = await readNdsRomMap(fixture.romPath);
  const scope = { kind: "components", arm9Main: true } as const;

  const integer = await searchNdsPattern(map, {
    kind: "integer",
    value: 0x12345678,
    width: 32,
    endian: "little",
    signed: false,
    alignment: 4,
  }, scope);
  assert.deepEqual(integer.matches.map((hit) => hit.romOffset), [0x210]);

  const ascii = await searchNdsPattern(map, { kind: "ascii", text: "HELLO" }, scope);
  assert.deepEqual(ascii.matches.map((hit) => hit.romOffset), [0x220]);

  const utf16 = await searchNdsPattern(map, { kind: "utf16le", text: "AΩ" }, scope);
  assert.deepEqual(utf16.matches.map((hit) => hit.romOffset), [0x230]);
});

test("searches compressed overlay stored bytes and exact NitroFS paths without runtime invention", async () => {
  const fixture = await createSearchFixture();
  const map = await readNdsRomMap(fixture.romPath);

  const overlay = await searchNdsPattern(
    map,
    { kind: "byte-signature", signature: "DE AD BE EF" },
    { kind: "components", arm9OverlayIds: [7] },
  );
  assert.deepEqual(overlay.matches.map((hit) => hit.romOffset), [0x1304]);
  const overlayOwner = overlay.matches[0]?.owners.find((owner) => owner.kind === "arm9-overlay");
  assert.equal(overlayOwner?.kind, "arm9-overlay");
  if (overlayOwner?.kind === "arm9-overlay") {
    assert.equal(overlayOwner.compressed, true);
    assert.equal(overlayOwner.runtimeAddress, null);
  }

  const file = await searchNdsPattern(
    map,
    { kind: "byte-signature", signature: "DE AD BE EF" },
    { kind: "components", nitroFsPaths: ["overlay.bin"] },
  );
  assert.deepEqual(file.matches.map((hit) => hit.romOffset), [0x1304]);
  assert.equal(file.matches[0]?.owners.some((owner) => owner.kind === "nitrofs-file"), true);
});

test("component scope rejects adjacent-file bridge while whole-ROM scope finds it", async () => {
  const fixture = await createSearchFixture();
  const map = await readNdsRomMap(fixture.romPath);
  const pattern = { kind: "byte-signature", signature: "CC DD" } as const;

  const componentResult = await searchNdsPattern(
    map,
    pattern,
    { kind: "components", nitroFsPaths: ["first.bin", "second.bin"] },
  );
  assert.deepEqual(componentResult.matches, []);
  assert.equal(componentResult.status, "complete");

  const wholeResult = await searchNdsPattern(map, pattern, { kind: "whole-rom" });
  assert.equal(wholeResult.matches.some((hit) => hit.romOffset === 0x121f), true);
});

test("clips component context to the deterministic containing component", async () => {
  const fixture = await createSearchFixture();
  const map = await readNdsRomMap(fixture.romPath);
  const result = await searchNdsPattern(
    map,
    { kind: "byte-signature", signature: "AA BB" },
    { kind: "components", nitroFsPaths: ["first.bin"] },
    { contextBytes: 4 },
  );

  assert.equal(result.matches.length, 1);
  assert.deepEqual(result.matches[0]?.context, {
    beforeHex: "11",
    afterHex: "00000000",
    clippedAtStart: true,
    clippedAtEnd: false,
  });
});

test("whole-ROM context clips only at ROM bounds", async () => {
  const fixture = await createSearchFixture();
  fixture.buffer.set([0xfa, 0xce], 0);
  fixture.buffer.set([0xba, 0xbe], fixture.buffer.length - 2);
  await fixture.write();
  const map = await readNdsRomMap(fixture.romPath);

  const first = await searchNdsPattern(
    map,
    { kind: "byte-signature", signature: "FA CE" },
    { kind: "whole-rom" },
    { contextBytes: 4 },
  );
  assert.equal(first.matches[0]?.context?.beforeHex, "");
  assert.equal(first.matches[0]?.context?.clippedAtStart, true);

  const last = await searchNdsPattern(
    map,
    { kind: "byte-signature", signature: "BA BE" },
    { kind: "whole-rom" },
    { contextBytes: 4 },
  );
  assert.equal(last.matches.at(-1)?.context?.afterHex, "");
  assert.equal(last.matches.at(-1)?.context?.clippedAtEnd, true);
});

test("rejects a ROM whose current hash no longer matches the canonical map", async () => {
  const fixture = await createSearchFixture();
  const map = await readNdsRomMap(fixture.romPath);
  fixture.buffer[0x200] = fixture.buffer[0x200]! ^ 0xff;
  await fixture.write();

  await assert.rejects(
    searchNdsPattern(
      map,
      { kind: "byte-signature", signature: "AA" },
      { kind: "whole-rom" },
    ),
    (error) => error instanceof NdsError && error.category === "invalid-rom",
  );
});

test("performs and enforces the post-scan SHA check", async () => {
  const fixture = await createSearchFixture();
  const map = await readNdsRomMap(fixture.romPath);
  let hashCalls = 0;

  await assert.rejects(
    searchNdsPattern(
      map,
      { kind: "byte-signature", signature: "AA" },
      { kind: "whole-rom" },
      {},
      {
        hashFileSha256: async () => (++hashCalls === 1 ? map.sha256 : "0".repeat(64)),
      },
    ),
    (error) => error instanceof NdsError && error.category === "invalid-rom",
  );
  assert.equal(hashCalls, 2);
});

test("validates context bounds independently of matcher limits", async () => {
  const fixture = await createSearchFixture();
  const map = await readNdsRomMap(fixture.romPath);
  await assert.rejects(
    searchNdsPattern(
      map,
      { kind: "byte-signature", signature: "AA" },
      { kind: "whole-rom" },
      { contextBytes: 65 },
    ),
    (error) => error instanceof NdsError && error.category === "pattern-search-limit-exceeded",
  );
});
