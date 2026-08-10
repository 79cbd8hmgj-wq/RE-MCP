import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

import { decodeNdsBlz } from "../src/services/nds/blz.js";
import { NdsError } from "../src/services/nds/errors.js";
import {
  createNdsOverlayRuntimeContext,
} from "../src/services/nds/overlay-runtime.js";
import { serializeNdsOverlayTable } from "../src/services/nds/overlays-serialize.js";
import { readNdsRomMap } from "../src/services/nds/rom-map.js";
import {
  assertNoNdsRebuildLogicalConflicts,
} from "../src/services/nds/mutation/conflicts.js";
import {
  planDecodedOverlayReplacement,
  type NdsDecodedOverlayReplacementPlan,
} from "../src/services/nds/mutation/overlay-plan.js";
import { createMutationFixture } from "./helpers/nds-mutation-fixture.js";

const ZERO_SHA = "0".repeat(64);

async function expectedOperation(
  fixture: Awaited<ReturnType<typeof createMutationFixture>>,
  replacementBytes?: Buffer,
) {
  const runtimeContext = createNdsOverlayRuntimeContext(fixture.map);
  const image = await runtimeContext.getCompressedOverlay(
    "arm9",
    fixture.compressedOverlayId,
  );
  const replacement = replacementBytes ?? (() => {
    const bytes = Buffer.from(image.bytes);
    bytes[0] = bytes[0]! ^ 0xff;
    return bytes;
  })();
  const artifact = await fixture.writeArtifact("artifacts/overlay7.dec.bin", replacement);
  return {
    runtimeContext,
    image,
    replacement,
    operation: {
      type: "replace-decoded-overlay" as const,
      target: {
        processor: "arm9" as const,
        overlayId: fixture.compressedOverlayId,
      },
      expectedStoredSha256: image.storedSha256,
      expectedRuntimeSha256: image.runtimeSha256,
      replacement: {
        artifact: artifact.relativePath,
        sha256: artifact.sha256,
      },
    },
  };
}

function assertCategory(
  promise: Promise<unknown>,
  expected: string,
): Promise<void> {
  return assert.rejects(promise, (error: unknown) => {
    assert.ok(error instanceof NdsError);
    assert.equal(error.category, expected);
    return true;
  });
}

test("decoded overlay replacement enforces stored/runtime/artifact guards and encodes deterministically", async () => {
  const fixture = await createMutationFixture();
  const prepared = await expectedOperation(fixture);

  const first = await planDecodedOverlayReplacement(
    fixture.map,
    fixture.directory,
    3,
    prepared.operation,
    prepared.runtimeContext,
  );
  const second = await planDecodedOverlayReplacement(
    fixture.map,
    fixture.directory,
    3,
    prepared.operation,
    createNdsOverlayRuntimeContext(fixture.map),
  );

  assert.equal(first.operationIndex, 3);
  assert.equal(first.processor, "arm9");
  assert.equal(first.overlayId, fixture.compressedOverlayId);
  assert.equal(first.fileId, fixture.compressedFileId);
  assert.equal(first.sourceStoredStart, fixture.compressedRomOffset);
  assert.equal(first.sourceStoredEnd, fixture.compressedRomOffset + prepared.image.storedSize);
  assert.equal(first.sourceStoredSha256, prepared.image.storedSha256);
  assert.equal(first.sourceRuntimeSha256, prepared.image.runtimeSha256);
  assert.equal(first.replacementRuntimeSha256, prepared.operation.replacement.sha256);
  assert.equal(first.runtimeSize, prepared.image.runtimeSize);
  assert.equal(first.encodedSize, first.encodedBytes.length);
  assert.equal(first.encodedSha256.length, 64);
  assert.deepEqual(first.encodedBytes, second.encodedBytes);
  assert.equal(first.encodedSha256, second.encodedSha256);
  assert.deepEqual(
    decodeNdsBlz(first.encodedBytes, first.runtimeSize).bytes,
    prepared.replacement,
  );
});

test("decoded overlay replacement rejects unknown, wrong-processor, and uncompressed overlays", async () => {
  const fixture = await createMutationFixture();
  const prepared = await expectedOperation(fixture);

  for (const target of [
    { processor: "arm9" as const, overlayId: 0xdead },
    { processor: "arm7" as const, overlayId: fixture.compressedOverlayId },
    { processor: "arm9" as const, overlayId: fixture.uncompressedOverlayId },
  ]) {
    await assertCategory(
      planDecodedOverlayReplacement(
        fixture.map,
        fixture.directory,
        0,
        { ...prepared.operation, target },
        createNdsOverlayRuntimeContext(fixture.map),
      ),
      "decoded-overlay-guard-failed",
    );
  }
});

test("decoded overlay replacement rejects source stored and runtime hash mismatches", async () => {
  const fixture = await createMutationFixture();
  const prepared = await expectedOperation(fixture);

  await assertCategory(
    planDecodedOverlayReplacement(
      fixture.map,
      fixture.directory,
      0,
      { ...prepared.operation, expectedStoredSha256: ZERO_SHA },
      createNdsOverlayRuntimeContext(fixture.map),
    ),
    "decoded-overlay-guard-failed",
  );
  await assertCategory(
    planDecodedOverlayReplacement(
      fixture.map,
      fixture.directory,
      0,
      { ...prepared.operation, expectedRuntimeSha256: ZERO_SHA },
      createNdsOverlayRuntimeContext(fixture.map),
    ),
    "decoded-overlay-guard-failed",
  );
});

test("decoded overlay replacement rejects artifact hash mismatch, size mismatch, and runtime no-op", async () => {
  const fixture = await createMutationFixture();
  const prepared = await expectedOperation(fixture);

  await assertCategory(
    planDecodedOverlayReplacement(
      fixture.map,
      fixture.directory,
      0,
      {
        ...prepared.operation,
        replacement: { ...prepared.operation.replacement, sha256: ZERO_SHA },
      },
      createNdsOverlayRuntimeContext(fixture.map),
    ),
    "replacement-artifact-hash-mismatch",
  );

  for (const size of [prepared.image.runtimeSize - 1, prepared.image.runtimeSize + 1]) {
    const bytes = Buffer.alloc(size, 0x41);
    const artifact = await fixture.writeArtifact(`artifacts/wrong-${size}.bin`, bytes);
    await assertCategory(
      planDecodedOverlayReplacement(
        fixture.map,
        fixture.directory,
        0,
        {
          ...prepared.operation,
          replacement: { artifact: artifact.relativePath, sha256: artifact.sha256 },
        },
        createNdsOverlayRuntimeContext(fixture.map),
      ),
      "decoded-overlay-guard-failed",
    );
  }

  const noOpArtifact = await fixture.writeArtifact("artifacts/noop.bin", prepared.image.bytes);
  await assertCategory(
    planDecodedOverlayReplacement(
      fixture.map,
      fixture.directory,
      0,
      {
        ...prepared.operation,
        replacement: { artifact: noOpArtifact.relativePath, sha256: noOpArtifact.sha256 },
      },
      createNdsOverlayRuntimeContext(fixture.map),
    ),
    "mutation-no-op",
  );
});

test("overlay table serializer changes only the targeted packed compressed-size bits and reparses", async () => {
  const fixture = await createMutationFixture();
  const prepared = await expectedOperation(fixture);
  const plan = await planDecodedOverlayReplacement(
    fixture.map,
    fixture.directory,
    0,
    prepared.operation,
    prepared.runtimeContext,
  );
  const sourceRom = await readFile(fixture.romPath);
  const table = fixture.map.header.arm9OverlayTable;
  const originalTable = sourceRom.subarray(table.offset, table.end);
  const serialized = serializeNdsOverlayTable(
    fixture.map.overlays.arm9,
    new Map([[fixture.compressedOverlayId, plan.encodedSize]]),
  );

  assert.equal(serialized.length, originalTable.length);
  for (let recordIndex = 0; recordIndex < fixture.map.overlays.arm9.length; recordIndex += 1) {
    const start = recordIndex * 32;
    const sourceRecord = originalTable.subarray(start, start + 32);
    const outputRecord = serialized.subarray(start, start + 32);
    const overlay = fixture.map.overlays.arm9[recordIndex]!;
    if (overlay.overlayId !== fixture.compressedOverlayId) {
      assert.deepEqual(outputRecord, sourceRecord);
      continue;
    }
    assert.deepEqual(outputRecord.subarray(0, 0x1c), sourceRecord.subarray(0, 0x1c));
    assert.equal(outputRecord[0x1f], sourceRecord[0x1f]);
    assert.equal(outputRecord.readUInt32LE(0x1c) >>> 24, overlay.flags);
    assert.equal(outputRecord.readUInt32LE(0x1c) & 0x00ff_ffff, plan.encodedSize);
  }

  const outputRom = Buffer.from(sourceRom);
  serialized.copy(outputRom, table.offset);
  const outputPath = path.join(fixture.directory, "overlay-table-reparse.nds");
  await writeFile(outputPath, outputRom);
  const reparsed = await readNdsRomMap(outputPath);
  const overlay = reparsed.overlays.arm9.find(
    (candidate) => candidate.overlayId === fixture.compressedOverlayId,
  );
  assert.equal(overlay?.compressedSize, plan.encodedSize);
  assert.equal(overlay?.flags, fixture.map.overlays.arm9[1]?.flags);
});

test("overlay table serializer rejects packed compressed-size overflow and unknown override IDs", async () => {
  const fixture = await createMutationFixture();

  assert.throws(
    () => serializeNdsOverlayTable(
      fixture.map.overlays.arm9,
      new Map([[fixture.compressedOverlayId, 0x0100_0000]]),
    ),
    (error: unknown) => error instanceof NdsError && error.category === "blz-packed-size-overflow",
  );
  assert.throws(
    () => serializeNdsOverlayTable(
      fixture.map.overlays.arm9,
      new Map([[0xdead, 12]]),
    ),
    (error: unknown) => error instanceof NdsError && error.category === "overlay-table-rebuild-failed",
  );
});

test("rebuild logical conflicts reject fixed or generic file mutation of decoded overlay backing", async () => {
  const fixture = await createMutationFixture();
  const prepared = await expectedOperation(fixture);
  const overlayPlan = await planDecodedOverlayReplacement(
    fixture.map,
    fixture.directory,
    2,
    prepared.operation,
    prepared.runtimeContext,
  );

  const fakeFixed = {
    type: "replace-component" as const,
    index: 0,
    target: { component: "arm9-overlay" as const, overlayId: fixture.compressedOverlayId },
    component: {
      component: "arm9-overlay" as const,
      processor: "arm9" as const,
      overlayId: fixture.compressedOverlayId,
      fileId: fixture.compressedFileId,
      filePath: "compressed.bin",
      romStart: overlayPlan.sourceStoredStart,
      romEnd: overlayPlan.sourceStoredEnd,
      size: overlayPlan.sourceStoredEnd - overlayPlan.sourceStoredStart,
      compressed: true,
      overlayOwners: [{ processor: "arm9" as const, overlayId: fixture.compressedOverlayId, compressed: true }],
    },
    romStart: overlayPlan.sourceStoredStart,
    romEnd: overlayPlan.sourceStoredEnd,
    size: overlayPlan.sourceStoredEnd - overlayPlan.sourceStoredStart,
    expectedOriginalSha256: overlayPlan.sourceStoredSha256,
    originalSha256: overlayPlan.sourceStoredSha256,
    replacement: {
      absolutePath: "/tmp/replacement",
      workspacePath: "replacement",
      sha256: "1".repeat(64),
      size: overlayPlan.sourceStoredEnd - overlayPlan.sourceStoredStart,
    },
  };

  assert.throws(
    () => assertNoNdsRebuildLogicalConflicts([fakeFixed], [], [overlayPlan]),
    (error: unknown) => error instanceof NdsError && error.category === "mutation-overlap",
  );

  const fakeRelocated = {
    operationIndex: 1,
    fileId: fixture.compressedFileId,
    filePath: "compressed.bin",
    sourceStart: overlayPlan.sourceStoredStart,
    sourceEnd: overlayPlan.sourceStoredEnd,
    sourceSha256: overlayPlan.sourceStoredSha256,
    replacementWorkspacePath: "ordinary.bin",
    replacementAbsolutePath: "/tmp/ordinary.bin",
    replacementSha256: "2".repeat(64),
    replacementSize: 10,
  };
  assert.throws(
    () => assertNoNdsRebuildLogicalConflicts([], [fakeRelocated], [overlayPlan]),
    (error: unknown) => error instanceof NdsError && error.category === "unsupported-rebuild-target",
  );
});
