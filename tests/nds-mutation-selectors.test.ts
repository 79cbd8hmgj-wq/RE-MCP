import assert from "node:assert/strict";
import test from "node:test";

import { NdsError } from "../src/services/nds/errors.js";
import {
  assertMutationRangeOutsideStructure,
  ndsImmutableStructuralRanges,
  resolveNdsMutationByteTarget,
  resolveNdsMutationComponent,
} from "../src/services/nds/mutation/selectors.js";
import { createMutationFixture } from "./helpers/nds-mutation-fixture.js";

test("resolves main, explicit overlay, and ordinary NitroFS components canonically", async () => {
  const fixture = await createMutationFixture();

  const arm9 = resolveNdsMutationComponent(fixture.map, { component: "arm9" });
  assert.equal(arm9.romStart, fixture.arm9Offset);
  assert.equal(arm9.processor, "arm9");

  const overlay = resolveNdsMutationComponent(fixture.map, {
    component: "arm9-overlay",
    overlayId: fixture.uncompressedOverlayId,
  });
  assert.equal(overlay.romStart, fixture.uncompressedRomOffset);
  assert.equal(overlay.overlayId, fixture.uncompressedOverlayId);
  assert.equal(overlay.compressed, false);

  const byId = resolveNdsMutationComponent(fixture.map, {
    component: "nitrofs-file",
    fileId: fixture.ordinaryFileId,
  });
  const byPath = resolveNdsMutationComponent(fixture.map, {
    component: "nitrofs-path",
    filePath: "asset.bin",
  });
  assert.equal(byId.romStart, byPath.romStart);
  assert.equal(byPath.fileId, fixture.ordinaryFileId);
});

test("rejects every overlay-backed NitroFS alias and requires the overlay selector", async () => {
  const fixture = await createMutationFixture();
  for (const selector of [
    { component: "nitrofs-file" as const, fileId: fixture.uncompressedFileId },
    { component: "nitrofs-path" as const, filePath: "overlay.bin" },
    { component: "nitrofs-file" as const, fileId: fixture.compressedFileId },
    { component: "nitrofs-path" as const, filePath: "compressed.bin" },
  ]) {
    assert.throws(
      () => resolveNdsMutationComponent(fixture.map, selector),
      (error: unknown) => error instanceof NdsError
        && error.category === "unsupported-mutation-target",
    );
  }
});

test("resolves an exact uncompressed overlay relative byte range", async () => {
  const fixture = await createMutationFixture();
  const target = resolveNdsMutationByteTarget(
    fixture.map,
    {
      component: "arm9-overlay",
      overlayId: fixture.uncompressedOverlayId,
      relativeOffset: 4,
    },
    2,
  );
  assert.equal(target.romStart, target.component.romStart + 4);
  assert.equal(target.romEnd, target.romStart + 2);
  assert.equal(target.component.overlayId, fixture.uncompressedOverlayId);
});

test("resolves unique main and exact-overlay runtime addresses", async () => {
  const fixture = await createMutationFixture();
  const main = resolveNdsMutationByteTarget(
    fixture.map,
    { component: "arm9", runtimeAddress: fixture.map.header.arm9.ramAddress + 8 },
    2,
  );
  assert.equal(main.relativeOffset, 8);
  assert.equal(main.romStart, fixture.arm9Offset + 8);

  const overlay = fixture.map.overlays.arm9.find(
    (candidate) => candidate.overlayId === fixture.uncompressedOverlayId,
  );
  assert.ok(overlay);
  const exact = resolveNdsMutationByteTarget(
    fixture.map,
    {
      component: "arm9-overlay",
      overlayId: fixture.uncompressedOverlayId,
      runtimeAddress: overlay.ramAddress + 6,
    },
    2,
  );
  assert.equal(exact.relativeOffset, 6);
});

test("rejects byte edits against stored compressed overlays", async () => {
  const fixture = await createMutationFixture();
  assert.throws(
    () => resolveNdsMutationByteTarget(
      fixture.map,
      {
        component: "arm9-overlay",
        overlayId: fixture.compressedOverlayId,
        relativeOffset: 0,
      },
      2,
    ),
    (error: unknown) => error instanceof NdsError
      && error.category === "unsupported-mutation-target",
  );
});

test("rejects ranges that cross component boundaries", async () => {
  const fixture = await createMutationFixture();
  const arm9 = resolveNdsMutationComponent(fixture.map, { component: "arm9" });
  assert.throws(
    () => resolveNdsMutationByteTarget(
      fixture.map,
      { component: "arm9", relativeOffset: arm9.size - 1 },
      2,
    ),
    (error: unknown) => error instanceof NdsError
      && error.category === "unsupported-mutation-target",
  );
});

test("marks the first 0x200 bytes and canonical tables as immutable structure", async () => {
  const fixture = await createMutationFixture();
  const ranges = ndsImmutableStructuralRanges(fixture.map);
  assert.equal(ranges[0]?.romStart, 0);
  assert.ok((ranges[0]?.romEnd ?? 0) >= 0x200);
  assert.throws(
    () => assertMutationRangeOutsideStructure(fixture.map, 0x40, 0x44),
    (error: unknown) => error instanceof NdsError
      && error.category === "structural-metadata-mutation",
  );
  assert.doesNotThrow(
    () => assertMutationRangeOutsideStructure(
      fixture.map,
      fixture.ordinaryRomOffset,
      fixture.ordinaryRomOffset + 2,
    ),
  );
});

test("rejects unknown canonical file and overlay selectors", async () => {
  const fixture = await createMutationFixture();
  assert.throws(
    () => resolveNdsMutationComponent(fixture.map, {
      component: "arm9-overlay",
      overlayId: 999,
    }),
    (error: unknown) => error instanceof NdsError && error.category === "unknown-overlay-id",
  );
  assert.throws(
    () => resolveNdsMutationComponent(fixture.map, {
      component: "nitrofs-file",
      fileId: 999,
    }),
    (error: unknown) => error instanceof NdsError && error.category === "unknown-file-id",
  );
});
