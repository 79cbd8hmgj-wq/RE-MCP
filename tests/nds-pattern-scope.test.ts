import assert from "node:assert/strict";
import test from "node:test";

import { NdsError } from "../src/services/nds/errors.js";
import {
  patternSpanIsEligible,
  resolveNdsPatternScope,
  selectPatternContextComponent,
  type ResolvedNdsPatternScope,
} from "../src/services/nds/pattern-scope.js";
import { readNdsRomMap } from "../src/services/nds/rom-map.js";
import {
  createNdsFixture,
  encodeFntFileEntry,
  writeFatEntry,
  writeFntMainRecord,
  writeFntSubtable,
  writeOverlayRecord,
} from "./helpers/nds-fixture.js";

async function createScopeFixture() {
  const fixture = await createNdsFixture({
    fileSize: 0x5000,
    fntSize: 0x40,
    fatSize: 16,
    arm9OverlaySize: 32,
  });
  writeFatEntry(fixture.buffer, 0x900, 0, 0x1200, 0x1220);
  writeFatEntry(fixture.buffer, 0x900, 1, 0x1300, 0x1380);
  writeFntMainRecord(fixture.buffer, 0x800, 0, 8, 0, 1);
  writeFntSubtable(fixture.buffer, 0x800, 8, [encodeFntFileEntry("asset.bin")]);
  writeOverlayRecord(fixture.buffer, 0xa00, 0, {
    overlayId: 7,
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
  return fixture;
}

function manualFile(
  key: string,
  start: number,
  end: number,
  fileId: number,
) {
  return {
    key,
    kind: "nitrofs-file" as const,
    start,
    end,
    processor: null,
    overlayId: null,
    fileId,
    path: `${key}.bin`,
    compressed: false,
  };
}

test("resolves and deduplicates canonical component selectors", async () => {
  const fixture = await createScopeFixture();
  const map = await readNdsRomMap(fixture.romPath);
  const resolved = resolveNdsPatternScope(map, {
    kind: "components",
    arm9Main: true,
    arm9OverlayIds: [7, 7],
    nitroFsFileIds: [0],
    nitroFsPaths: ["asset.bin"],
  });

  assert.equal(
    resolved.components.filter((component) => component.kind === "arm9-main").length,
    1,
  );
  assert.equal(
    resolved.components.filter((component) => component.kind === "arm9-overlay").length,
    1,
  );
  assert.equal(
    resolved.components.filter((component) => component.kind === "nitrofs-file").length,
    1,
  );
});

test("normalizes overlapping physical relationships without losing provenance", async () => {
  const fixture = await createScopeFixture();
  const map = await readNdsRomMap(fixture.romPath);
  const resolved = resolveNdsPatternScope(map, {
    kind: "components",
    arm9OverlayIds: [7],
    nitroFsFileIds: [1],
  });

  assert.equal(resolved.components.length, 2);
  assert.deepEqual(resolved.physicalRanges, [{ start: 0x1300, end: 0x1380 }]);
  assert.equal(patternSpanIsEligible(resolved, 0x1304, 0x1310), true);
});

test("requires a full candidate span inside one selected component", () => {
  const adjacent: ResolvedNdsPatternScope = {
    kind: "components",
    components: [manualFile("file:0", 0, 2, 0), manualFile("file:1", 2, 4, 1)],
    physicalRanges: [{ start: 0, end: 4 }],
  };
  assert.equal(patternSpanIsEligible(adjacent, 1, 3), false);

  const overlapping: ResolvedNdsPatternScope = {
    kind: "components",
    components: [manualFile("file:0", 0, 4, 0), manualFile("file:1", 2, 6, 1)],
    physicalRanges: [{ start: 0, end: 6 }],
  };
  assert.equal(patternSpanIsEligible(overlapping, 1, 3), true);
  assert.equal(patternSpanIsEligible(overlapping, 3, 5), true);
});

test("whole ROM scope covers the complete physical ROM", async () => {
  const fixture = await createScopeFixture();
  const map = await readNdsRomMap(fixture.romPath);
  const resolved = resolveNdsPatternScope(map, { kind: "whole-rom" });
  assert.deepEqual(resolved.components, []);
  assert.deepEqual(resolved.physicalRanges, [{ start: 0, end: map.fileSize }]);
  assert.equal(patternSpanIsEligible(resolved, map.fileSize - 2, map.fileSize), true);
  assert.equal(patternSpanIsEligible(resolved, map.fileSize - 1, map.fileSize + 1), false);
});

test("rejects empty scopes and unknown canonical selectors", async () => {
  const fixture = await createScopeFixture();
  const map = await readNdsRomMap(fixture.romPath);

  assert.throws(
    () => resolveNdsPatternScope(map, { kind: "components" }),
    (error) => error instanceof NdsError && error.category === "invalid-pattern-scope",
  );
  assert.throws(
    () => resolveNdsPatternScope(map, { kind: "components", arm9OverlayIds: [999] }),
    (error) => error instanceof NdsError && error.category === "unknown-overlay-id",
  );
  assert.throws(
    () => resolveNdsPatternScope(map, { kind: "components", nitroFsFileIds: [999] }),
    (error) => error instanceof NdsError && error.category === "unknown-file-id",
  );
  assert.throws(
    () => resolveNdsPatternScope(map, { kind: "components", nitroFsPaths: ["missing.bin"] }),
    (error) => error instanceof NdsError && error.category === "unknown-file-id",
  );
});

test("enforces combined selector and canonical component caps", async () => {
  const fixture = await createScopeFixture();
  const map = await readNdsRomMap(fixture.romPath);
  assert.throws(
    () => resolveNdsPatternScope(map, {
      kind: "components",
      arm9OverlayIds: Array.from({ length: 129 }, (_, index) => index),
    }),
    (error) => error instanceof NdsError && error.category === "pattern-search-limit-exceeded",
  );
  assert.throws(
    () => resolveNdsPatternScope(map, {
      kind: "components",
      nitroFsFileIds: Array.from({ length: 257 }, (_, index) => index),
    }),
    (error) => error instanceof NdsError && error.category === "pattern-search-limit-exceeded",
  );

  const many = await createNdsFixture({
    fileSize: 0x8000,
    fntSize: 0,
    fatSize: 256 * 8,
  });
  for (let fileId = 0; fileId < 256; fileId += 1) {
    const start = 0x2000 + fileId * 4;
    writeFatEntry(many.buffer, 0x900, fileId, start, start + 4);
  }
  await many.write();
  const manyMap = await readNdsRomMap(many.romPath);
  assert.throws(
    () => resolveNdsPatternScope(manyMap, {
      kind: "components",
      arm9Main: true,
      nitroFsFileIds: Array.from({ length: 256 }, (_, index) => index),
    }),
    (error) => error instanceof NdsError && error.category === "pattern-search-limit-exceeded",
  );
});

test("selects deterministic greatest containing component for context", () => {
  const scope: ResolvedNdsPatternScope = {
    kind: "components",
    components: [
      manualFile("small", 2, 8, 1),
      manualFile("large", 0, 10, 2),
    ],
    physicalRanges: [{ start: 0, end: 10 }],
  };
  assert.equal(selectPatternContextComponent(scope, 3, 5)?.key, "large");

  const tied: ResolvedNdsPatternScope = {
    kind: "components",
    components: [
      manualFile("z", 0, 10, 9),
      manualFile("a", 0, 10, 1),
    ],
    physicalRanges: [{ start: 0, end: 10 }],
  };
  assert.equal(selectPatternContextComponent(tied, 3, 5)?.fileId, 1);
  assert.equal(selectPatternContextComponent({
    kind: "whole-rom",
    components: [],
    physicalRanges: [{ start: 0, end: 10 }],
  }, 3, 5), null);
});
