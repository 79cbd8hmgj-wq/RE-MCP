import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { open, readFile, truncate } from "node:fs/promises";
import test from "node:test";

import { NdsError } from "../src/services/nds/errors.js";
import { applyNdsMutationPlan } from "../src/services/nds/mutation/apply.js";
import { loadNdsMutationManifest } from "../src/services/nds/mutation/manifest.js";
import { compileNdsMutationPlan } from "../src/services/nds/mutation/planner.js";
import {
  cleanupNdsMutationStage,
  createNdsMutationStage,
} from "../src/services/nds/mutation/staging.js";
import { verifyNdsMutationOutput } from "../src/services/nds/mutation/verify.js";
import { createMutationFixture } from "./helpers/nds-mutation-fixture.js";

function sha256(bytes: Buffer): string {
  return createHash("sha256").update(bytes).digest("hex");
}

async function appliedByteBuild() {
  const fixture = await createMutationFixture();
  const source = await readFile(fixture.romPath);
  const manifestPath = await fixture.writeManifest({
    outputFilename: "verified.nds",
    operations: [{
      type: "replace-bytes",
      target: { component: "arm9", relativeOffset: 0 },
      expected: source.subarray(fixture.arm9Offset, fixture.arm9Offset + 2).toString("hex"),
      replacement: "1234",
    }],
  });
  const loaded = await loadNdsMutationManifest(fixture.directory, manifestPath);
  const plan = await compileNdsMutationPlan(fixture.map, fixture.directory, loaded);
  const stage = await createNdsMutationStage(plan, fixture.directory);
  await applyNdsMutationPlan(plan, stage);
  return { fixture, plan, stage };
}

async function overwriteByte(filePath: string, offset: number, value: number): Promise<void> {
  const handle = await open(filePath, "r+");
  try {
    await handle.write(Buffer.from([value]), 0, 1, offset);
    await handle.sync();
  } finally {
    await handle.close();
  }
}

test("verifies a valid output and attributes every changed byte", async () => {
  const { fixture, plan, stage } = await appliedByteBuild();
  try {
    const result = await verifyNdsMutationOutput(fixture.map, plan, stage.stagedRomPath);
    assert.equal(result.status, "passed");
    assert.equal(result.sourceSha256, plan.sourceSha256);
    assert.equal(result.outputSize, plan.sourceSize);
    assert.equal(result.sourceUnchanged, true);
    assert.equal(result.structuralMetadataUnchanged, true);
    assert.equal(result.structuralMapUnchanged, true);
    assert.equal(result.unexpectedChangedBytes, 0);
    assert.ok(result.changedByteCount > 0);
    assert.deepEqual(result.operations.map((entry) => entry.index), [0]);
  } finally {
    await cleanupNdsMutationStage(stage);
  }
});

test("rejects output size changes and parser-invalid output", async () => {
  const first = await appliedByteBuild();
  try {
    await truncate(first.stage.stagedRomPath, first.plan.sourceSize - 1);
    await assert.rejects(
      verifyNdsMutationOutput(first.fixture.map, first.plan, first.stage.stagedRomPath),
      (error: unknown) => error instanceof NdsError
        && error.category === "output-verification-failed",
    );
  } finally {
    await cleanupNdsMutationStage(first.stage);
  }

  const second = await appliedByteBuild();
  try {
    const handle = await open(second.stage.stagedRomPath, "r+");
    try {
      const zeroSize = Buffer.alloc(4);
      await handle.write(zeroSize, 0, zeroSize.length, 0x2c);
      await handle.sync();
    } finally {
      await handle.close();
    }
    await assert.rejects(
      verifyNdsMutationOutput(second.fixture.map, second.plan, second.stage.stagedRomPath),
      (error: unknown) => error instanceof NdsError
        && error.category === "post-build-parse-failed",
    );
  } finally {
    await cleanupNdsMutationStage(second.stage);
  }
});

test("rejects immutable structural metadata changes", async () => {
  const { fixture, plan, stage } = await appliedByteBuild();
  try {
    const original = (await readFile(stage.stagedRomPath)).readUInt8(0x10);
    await overwriteByte(stage.stagedRomPath, 0x10, original ^ 0xff);
    await assert.rejects(
      verifyNdsMutationOutput(fixture.map, plan, stage.stagedRomPath),
      (error: unknown) => error instanceof NdsError
        && error.category === "structural-map-changed",
    );
  } finally {
    await cleanupNdsMutationStage(stage);
  }
});

test("rejects a missing requested mutation and any unrelated changed byte", async () => {
  const missing = await appliedByteBuild();
  try {
    const source = await readFile(missing.fixture.romPath);
    const handle = await open(missing.stage.stagedRomPath, "r+");
    try {
      await handle.write(source, missing.fixture.arm9Offset, 2, missing.fixture.arm9Offset);
      await handle.sync();
    } finally {
      await handle.close();
    }
    await assert.rejects(
      verifyNdsMutationOutput(missing.fixture.map, missing.plan, missing.stage.stagedRomPath),
      (error: unknown) => error instanceof NdsError
        && error.category === "output-verification-failed",
    );
  } finally {
    await cleanupNdsMutationStage(missing.stage);
  }

  const unexpected = await appliedByteBuild();
  try {
    const original = (await readFile(unexpected.stage.stagedRomPath))
      .readUInt8(unexpected.fixture.unrelatedRomOffset);
    await overwriteByte(
      unexpected.stage.stagedRomPath,
      unexpected.fixture.unrelatedRomOffset,
      original ^ 0xff,
    );
    await assert.rejects(
      verifyNdsMutationOutput(
        unexpected.fixture.map,
        unexpected.plan,
        unexpected.stage.stagedRomPath,
      ),
      (error: unknown) => error instanceof NdsError
        && error.category === "unexpected-rom-diff",
    );
  } finally {
    await cleanupNdsMutationStage(unexpected.stage);
  }
});

test("verifies whole-component replacement hashes", async () => {
  const fixture = await createMutationFixture();
  const source = await readFile(fixture.romPath);
  const arm7 = fixture.map.header.arm7;
  const original = source.subarray(arm7.romOffset, arm7.romEnd);
  const replacement = Buffer.alloc(original.length, 0x31);
  const artifact = await fixture.writeArtifact("artifacts/verify-arm7.bin", replacement);
  const manifestPath = await fixture.writeManifest({
    outputFilename: "component.nds",
    operations: [{
      type: "replace-component",
      target: { component: "arm7" },
      expectedOriginalSha256: sha256(original),
      replacement: { artifact: artifact.relativePath, sha256: artifact.sha256 },
    }],
  });
  const loaded = await loadNdsMutationManifest(fixture.directory, manifestPath);
  const plan = await compileNdsMutationPlan(fixture.map, fixture.directory, loaded);
  const stage = await createNdsMutationStage(plan, fixture.directory);
  try {
    await applyNdsMutationPlan(plan, stage);
    await assert.doesNotReject(
      verifyNdsMutationOutput(fixture.map, plan, stage.stagedRomPath),
    );
    await overwriteByte(stage.stagedRomPath, arm7.romOffset, 0x32);
    await assert.rejects(
      verifyNdsMutationOutput(fixture.map, plan, stage.stagedRomPath),
      (error: unknown) => error instanceof NdsError
        && error.category === "output-verification-failed",
    );
  } finally {
    await cleanupNdsMutationStage(stage);
  }
});

test("revalidates exact-size compressed overlay replacements as runtime images", async () => {
  const fixture = await createMutationFixture();
  const source = await readFile(fixture.romPath);
  const overlay = fixture.map.overlays.arm9.find(
    (candidate) => candidate.overlayId === fixture.compressedOverlayId,
  );
  assert.ok(overlay);
  const original = source.subarray(overlay.romOffset, overlay.romOffset + overlay.romSize);
  const replacement = Buffer.from(original);
  replacement[replacement.length - 1] = replacement[replacement.length - 1] === 0x5a ? 0x5b : 0x5a;
  const artifact = await fixture.writeArtifact("artifacts/verify-compressed.bin", replacement);
  const manifestPath = await fixture.writeManifest({
    outputFilename: "compressed.nds",
    operations: [{
      type: "replace-component",
      target: { component: "arm9-overlay", overlayId: fixture.compressedOverlayId },
      expectedOriginalSha256: sha256(original),
      replacement: { artifact: artifact.relativePath, sha256: artifact.sha256 },
    }],
  });
  const loaded = await loadNdsMutationManifest(fixture.directory, manifestPath);
  const plan = await compileNdsMutationPlan(fixture.map, fixture.directory, loaded);
  const stage = await createNdsMutationStage(plan, fixture.directory);
  try {
    await applyNdsMutationPlan(plan, stage);
    const result = await verifyNdsMutationOutput(fixture.map, plan, stage.stagedRomPath);
    assert.deepEqual(
      result.compressedOverlays.map((entry) => [entry.processor, entry.overlayId, entry.status]),
      [["arm9", fixture.compressedOverlayId, "passed"]],
    );
    assert.match(result.compressedOverlays[0]?.runtimeSha256 ?? "", /^[0-9a-f]{64}$/u);
  } finally {
    await cleanupNdsMutationStage(stage);
  }
});

test("fails if the immutable source changes after planning", async () => {
  const { fixture, plan, stage } = await appliedByteBuild();
  try {
    const original = (await readFile(fixture.romPath)).readUInt8(fixture.unrelatedRomOffset);
    await overwriteByte(fixture.romPath, fixture.unrelatedRomOffset, original ^ 0xff);
    await assert.rejects(
      verifyNdsMutationOutput(fixture.map, plan, stage.stagedRomPath),
      (error: unknown) => error instanceof NdsError && error.category === "source-rom-mismatch",
    );
  } finally {
    await cleanupNdsMutationStage(stage);
  }
});

test("rejects a staged ROM that changes after diff verification", async () => {
  const { fixture, plan, stage } = await appliedByteBuild();
  try {
    await assert.rejects(
      verifyNdsMutationOutput(
        fixture.map,
        plan,
        stage.stagedRomPath,
        {
          async afterDiff() {
            const current = (await readFile(stage.stagedRomPath))
              .readUInt8(fixture.unrelatedRomOffset);
            await overwriteByte(
              stage.stagedRomPath,
              fixture.unrelatedRomOffset,
              current ^ 0xff,
            );
          },
        },
      ),
      (error: unknown) => error instanceof NdsError
        && error.category === "output-verification-failed",
    );
  } finally {
    await cleanupNdsMutationStage(stage);
  }
});
