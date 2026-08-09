import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { NdsError } from "../src/services/nds/errors.js";
import { serializeNdsFat } from "../src/services/nds/fat-serialize.js";
import {
  assertNoNdsRebuildLogicalConflicts,
} from "../src/services/nds/mutation/conflicts.js";
import { guardNdsMutationOperation } from "../src/services/nds/mutation/guards.js";
import {
  planNdsVariableFileReplacement,
  type NdsVariableFilePlanningIo,
} from "../src/services/nds/mutation/filesystem-plan.js";
import type { NdsReplaceNitroFsFileOperation } from "../src/services/nds/mutation/manifest.js";
import { createMutationFixture } from "./helpers/nds-mutation-fixture.js";

function sha256(bytes: Buffer): string {
  return createHash("sha256").update(bytes).digest("hex");
}

test("serializes exact checked FAT entries", () => {
  const bytes = serializeNdsFat([
    { fileId: 0, startOffset: 0x1000, endOffset: 0x1010 },
    { fileId: 1, startOffset: 0x1200, endOffset: 0x1230 },
  ]);
  assert.equal(bytes.length, 16);
  assert.equal(bytes.readUInt32LE(0), 0x1000);
  assert.equal(bytes.readUInt32LE(4), 0x1010);
  assert.equal(bytes.readUInt32LE(8), 0x1200);
  assert.equal(bytes.readUInt32LE(12), 0x1230);
});

test("FAT serializer rejects gaps, inverted ranges, overlaps, and u32 overflow", () => {
  const invalid = [
    [
      { fileId: 1, startOffset: 0x1000, endOffset: 0x1010 },
    ],
    [
      { fileId: 0, startOffset: 0x1010, endOffset: 0x1000 },
    ],
    [
      { fileId: 0, startOffset: 0x1000, endOffset: 0x1100 },
      { fileId: 1, startOffset: 0x1080, endOffset: 0x1200 },
    ],
    [
      { fileId: 0, startOffset: 0x1_0000_0000, endOffset: 0x1_0000_0000 },
    ],
  ];
  for (const entries of invalid) {
    assert.throws(
      () => serializeNdsFat(entries),
      (error: unknown) => error instanceof NdsError
        && error.category === "fat-rebuild-failed",
    );
  }
});

async function replacementOperation(
  fixture: Awaited<ReturnType<typeof createMutationFixture>>,
  artifactBytes: Buffer,
  target: NdsReplaceNitroFsFileOperation["target"] = { fileId: fixture.ordinaryFileId },
) {
  const source = await readFile(fixture.romPath);
  const sourceBytes = source.subarray(
    fixture.ordinaryRomOffset,
    fixture.ordinaryRomOffset + 0x20,
  );
  const artifact = await fixture.writeArtifact(
    `patches/replacement-${artifactBytes.length}-${artifactBytes[0] ?? 0}.bin`,
    artifactBytes,
  );
  const operation: NdsReplaceNitroFsFileOperation = {
    type: "replace-nitrofs-file",
    target,
    expectedOriginalSha256: sha256(sourceBytes),
    replacement: { artifact: artifact.relativePath, sha256: artifact.sha256 },
  };
  return { operation, sourceBytes };
}

test("plans smaller, equal, and larger existing-file replacements without choosing output offsets", async () => {
  const fixture = await createMutationFixture();
  for (const size of [0x10, 0x20, 0x30]) {
    const bytes = Buffer.alloc(size, 0x70 + size);
    const { operation } = await replacementOperation(fixture, bytes);
    const plan = await planNdsVariableFileReplacement(
      fixture.map,
      fixture.directory,
      size,
      operation,
    );
    assert.equal(plan.operationIndex, size);
    assert.equal(plan.fileId, fixture.ordinaryFileId);
    assert.equal(plan.filePath, "asset.bin");
    assert.equal(plan.sourceStart, fixture.ordinaryRomOffset);
    assert.equal(plan.sourceEnd, fixture.ordinaryRomOffset + 0x20);
    assert.equal(plan.replacementSize, size);
    assert.equal(plan.replacementSha256, sha256(bytes));
    assert.equal("outputOffset" in plan, false);
  }
});

test("rejects overlay-backed aliases and stale/no-op replacement guards", async () => {
  const fixture = await createMutationFixture();
  const source = await readFile(fixture.romPath);
  const ordinary = source.subarray(fixture.ordinaryRomOffset, fixture.ordinaryRomOffset + 0x20);
  const same = await fixture.writeArtifact("patches/same.bin", ordinary);

  const overlayArtifact = await fixture.writeArtifact("patches/overlay-replacement.bin", Buffer.alloc(0x20, 0x99));
  for (const fileId of [fixture.uncompressedFileId, fixture.compressedFileId]) {
    const operation: NdsReplaceNitroFsFileOperation = {
      type: "replace-nitrofs-file",
      target: { fileId },
      expectedOriginalSha256: "0".repeat(64),
      replacement: {
        artifact: overlayArtifact.relativePath,
        sha256: overlayArtifact.sha256,
      },
    };
    await assert.rejects(
      planNdsVariableFileReplacement(fixture.map, fixture.directory, fileId, operation),
      (error: unknown) => error instanceof NdsError
        && error.category === "unsupported-rebuild-target",
    );
  }

  const stale: NdsReplaceNitroFsFileOperation = {
    type: "replace-nitrofs-file",
    target: { fileId: fixture.ordinaryFileId },
    expectedOriginalSha256: "0".repeat(64),
    replacement: { artifact: same.relativePath, sha256: same.sha256 },
  };
  await assert.rejects(
    planNdsVariableFileReplacement(fixture.map, fixture.directory, 10, stale),
    (error: unknown) => error instanceof NdsError
      && error.category === "original-component-guard-failed",
  );

  const noOp: NdsReplaceNitroFsFileOperation = {
    ...stale,
    expectedOriginalSha256: sha256(ordinary),
  };
  await assert.rejects(
    planNdsVariableFileReplacement(fixture.map, fixture.directory, 11, noOp),
    (error: unknown) => error instanceof NdsError
      && error.category === "mutation-no-op",
  );
});

test("rejects empty and oversized variable replacement artifacts before reading oversized data", async () => {
  const fixture = await createMutationFixture();
  const source = await readFile(fixture.romPath);
  const sourceHash = sha256(source.subarray(fixture.ordinaryRomOffset, fixture.ordinaryRomOffset + 0x20));
  const makeOperation = (artifact: string): NdsReplaceNitroFsFileOperation => ({
    type: "replace-nitrofs-file",
    target: { fileId: fixture.ordinaryFileId },
    expectedOriginalSha256: sourceHash,
    replacement: { artifact, sha256: "0".repeat(64) },
  });

  for (const size of [0, (64 * 1024 * 1024) + 1]) {
    let reads = 0;
    const io: NdsVariableFilePlanningIo = {
      async lstat() {
        return { isFile: () => true, isSymbolicLink: () => false, size };
      },
      async readFile() {
        reads += 1;
        return Buffer.alloc(0);
      },
    };
    await assert.rejects(
      planNdsVariableFileReplacement(
        fixture.map,
        fixture.directory,
        0,
        makeOperation(`virtual/${size}.bin`),
        io,
      ),
      (error: unknown) => error instanceof NdsError
        && error.category === "unsupported-rebuild-target",
    );
    assert.equal(reads, 0);
  }
});

test("rejects fixed-byte overlap and duplicate logical variable replacements", async () => {
  const fixture = await createMutationFixture();
  const source = await readFile(fixture.romPath);
  const expected = source.subarray(fixture.ordinaryRomOffset, fixture.ordinaryRomOffset + 2).toString("hex");
  const fixed = await guardNdsMutationOperation(
    fixture.map,
    fixture.directory,
    50,
    {
      type: "replace-bytes",
      target: { component: "nitrofs-file", fileId: fixture.ordinaryFileId, relativeOffset: 0 },
      expected,
      replacement: expected === "1234" ? "5678" : "1234",
    },
  );
  const firstInput = await replacementOperation(fixture, Buffer.alloc(0x18, 0x45));
  const secondInput = await replacementOperation(
    fixture,
    Buffer.alloc(0x28, 0x46),
    { filePath: "asset.bin" },
  );
  const first = await planNdsVariableFileReplacement(
    fixture.map,
    fixture.directory,
    1,
    firstInput.operation,
  );
  const second = await planNdsVariableFileReplacement(
    fixture.map,
    fixture.directory,
    2,
    secondInput.operation,
  );

  assert.throws(
    () => assertNoNdsRebuildLogicalConflicts([fixed], [first]),
    (error: unknown) => error instanceof NdsError && error.category === "mutation-overlap",
  );
  assert.throws(
    () => assertNoNdsRebuildLogicalConflicts([], [first, second]),
    (error: unknown) => error instanceof NdsError
      && error.category === "unsupported-rebuild-target",
  );
});
