import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

import { NdsError } from "../src/services/nds/errors.js";
import {
  assertNdsMutationSourceIdentity,
  guardNdsMutationOperation,
} from "../src/services/nds/mutation/guards.js";
import type { NdsMutationOperation } from "../src/services/nds/mutation/manifest.js";
import { createMutationFixture } from "./helpers/nds-mutation-fixture.js";

function sha256(bytes: Buffer): string {
  return createHash("sha256").update(bytes).digest("hex");
}

async function sourceComponentBytes(
  romPath: string,
  start: number,
  end: number,
): Promise<Buffer> {
  return (await readFile(romPath)).subarray(start, end);
}

test("guards exact source identity and expected original bytes", async () => {
  const fixture = await createMutationFixture();
  await assert.doesNotReject(
    assertNdsMutationSourceIdentity(fixture.map, fixture.sourceSha256),
  );

  const operation: NdsMutationOperation = {
    type: "replace-bytes",
    target: { component: "arm9", relativeOffset: 0 },
    expected: "a9a9",
    replacement: "1234",
  };
  const guarded = await guardNdsMutationOperation(
    fixture.map,
    fixture.directory,
    0,
    operation,
  );
  assert.equal(guarded.type, "replace-bytes");
  assert.equal(guarded.romStart, fixture.arm9Offset);
  assert.equal(guarded.romEnd, fixture.arm9Offset + 2);
});

test("fails before mutation when expected original bytes are stale", async () => {
  const fixture = await createMutationFixture();
  await assert.rejects(
    guardNdsMutationOperation(
      fixture.map,
      fixture.directory,
      0,
      {
        type: "replace-bytes",
        target: { component: "arm9", relativeOffset: 0 },
        expected: "ffff",
        replacement: "1234",
      },
    ),
    (error: unknown) => error instanceof NdsError
      && error.category === "original-byte-guard-failed",
  );
});

test("guards full component source hash, artifact hash, and exact size", async () => {
  const fixture = await createMutationFixture();
  const component = fixture.map.header.arm7;
  const source = await sourceComponentBytes(
    fixture.romPath,
    component.romOffset,
    component.romEnd,
  );
  const replacement = Buffer.alloc(source.length, 0x3c);
  const artifact = await fixture.writeArtifact("artifacts/arm7.bin", replacement);
  const guarded = await guardNdsMutationOperation(
    fixture.map,
    fixture.directory,
    0,
    {
      type: "replace-component",
      target: { component: "arm7" },
      expectedOriginalSha256: sha256(source),
      replacement: {
        artifact: artifact.relativePath,
        sha256: artifact.sha256,
      },
    },
  );
  assert.equal(guarded.type, "replace-component");
  if (guarded.type === "replace-component") {
    assert.equal(guarded.replacement.sha256, artifact.sha256);
    assert.equal(guarded.replacement.size, source.length);
    assert.equal(guarded.replacement.workspacePath, "artifacts/arm7.bin");
  }
});

test("rejects stale component hashes, missing artifacts, hash mismatches, and wrong sizes", async () => {
  const fixture = await createMutationFixture();
  const component = fixture.map.header.arm7;
  const source = await sourceComponentBytes(
    fixture.romPath,
    component.romOffset,
    component.romEnd,
  );
  const sourceHash = sha256(source);
  const validBytes = Buffer.alloc(source.length, 0x3c);
  const artifact = await fixture.writeArtifact("artifacts/arm7.bin", validBytes);

  const base = {
    type: "replace-component" as const,
    target: { component: "arm7" as const },
    expectedOriginalSha256: sourceHash,
    replacement: { artifact: artifact.relativePath, sha256: artifact.sha256 },
  };

  await assert.rejects(
    guardNdsMutationOperation(fixture.map, fixture.directory, 0, {
      ...base,
      expectedOriginalSha256: "0".repeat(64),
    }),
    (error: unknown) => error instanceof NdsError
      && error.category === "original-component-guard-failed",
  );

  await assert.rejects(
    guardNdsMutationOperation(fixture.map, fixture.directory, 0, {
      ...base,
      replacement: { artifact: "artifacts/missing.bin", sha256: artifact.sha256 },
    }),
    (error: unknown) => error instanceof NdsError
      && error.category === "replacement-artifact-missing",
  );

  await assert.rejects(
    guardNdsMutationOperation(fixture.map, fixture.directory, 0, {
      ...base,
      replacement: { artifact: artifact.relativePath, sha256: "1".repeat(64) },
    }),
    (error: unknown) => error instanceof NdsError
      && error.category === "replacement-artifact-hash-mismatch",
  );

  const short = await fixture.writeArtifact(
    "artifacts/short.bin",
    Buffer.alloc(source.length - 1, 0x3c),
  );
  await assert.rejects(
    guardNdsMutationOperation(fixture.map, fixture.directory, 0, {
      ...base,
      replacement: { artifact: short.relativePath, sha256: short.sha256 },
    }),
    (error: unknown) => error instanceof NdsError
      && error.category === "replacement-size-mismatch",
  );
});

test("rejects replacement artifacts that alias the source ROM", async () => {
  const fixture = await createMutationFixture();
  const component = fixture.map.header.arm7;
  const source = await sourceComponentBytes(
    fixture.romPath,
    component.romOffset,
    component.romEnd,
  );
  await assert.rejects(
    guardNdsMutationOperation(fixture.map, fixture.directory, 0, {
      type: "replace-component",
      target: { component: "arm7" },
      expectedOriginalSha256: sha256(source),
      replacement: {
        artifact: path.basename(fixture.romPath),
        sha256: fixture.sourceSha256,
      },
    }),
    (error: unknown) => error instanceof NdsError
      && error.category === "unsupported-mutation-target",
  );
});

test("rejects a whole-component replacement that is byte-identical to the source", async () => {
  const fixture = await createMutationFixture();
  const component = fixture.map.header.arm7;
  const source = await sourceComponentBytes(
    fixture.romPath,
    component.romOffset,
    component.romEnd,
  );
  const artifact = await fixture.writeArtifact("artifacts/no-op.bin", source);
  await assert.rejects(
    guardNdsMutationOperation(fixture.map, fixture.directory, 0, {
      type: "replace-component",
      target: { component: "arm7" },
      expectedOriginalSha256: sha256(source),
      replacement: { artifact: artifact.relativePath, sha256: artifact.sha256 },
    }),
    (error: unknown) => error instanceof NdsError
      && error.category === "mutation-no-op",
  );
});

test("accepts an exact-size stored compressed replacement only when its BLZ payload remains valid", async () => {
  const fixture = await createMutationFixture();
  const overlay = fixture.map.overlays.arm9.find(
    (candidate) => candidate.overlayId === fixture.compressedOverlayId,
  );
  assert.ok(overlay);
  const source = await sourceComponentBytes(
    fixture.romPath,
    overlay.romOffset,
    overlay.romOffset + overlay.romSize,
  );
  const validReplacement = Buffer.from(source);
  const trailingIndex = validReplacement.length - 1;
  validReplacement.writeUInt8(validReplacement.readUInt8(trailingIndex) ^ 0x01, trailingIndex);
  const validArtifact = await fixture.writeArtifact(
    "artifacts/compressed-valid.bin",
    validReplacement,
  );

  await assert.doesNotReject(
    guardNdsMutationOperation(fixture.map, fixture.directory, 0, {
      type: "replace-component",
      target: { component: "arm9-overlay", overlayId: fixture.compressedOverlayId },
      expectedOriginalSha256: sha256(source),
      replacement: {
        artifact: validArtifact.relativePath,
        sha256: validArtifact.sha256,
      },
    }),
  );

  const invalidReplacement = Buffer.alloc(source.length, 0);
  const invalidArtifact = await fixture.writeArtifact(
    "artifacts/compressed-invalid.bin",
    invalidReplacement,
  );
  await assert.rejects(
    guardNdsMutationOperation(fixture.map, fixture.directory, 0, {
      type: "replace-component",
      target: { component: "arm9-overlay", overlayId: fixture.compressedOverlayId },
      expectedOriginalSha256: sha256(source),
      replacement: {
        artifact: invalidArtifact.relativePath,
        sha256: invalidArtifact.sha256,
      },
    }),
    (error: unknown) => error instanceof NdsError
      && error.category === "compressed-overlay-invalid",
  );
});
