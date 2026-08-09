import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { NdsError } from "../src/services/nds/errors.js";
import { loadNdsMutationManifest } from "../src/services/nds/mutation/manifest.js";
import {
  compileNdsMutationPlan,
  serializeResolvedNdsMutationPlan,
} from "../src/services/nds/mutation/planner.js";
import { createMutationFixture } from "./helpers/nds-mutation-fixture.js";

function sha256(bytes: Buffer): string {
  return createHash("sha256").update(bytes).digest("hex");
}

test("compiles disjoint guarded operations into a deterministic read-only plan", async () => {
  const fixture = await createMutationFixture();
  const manifestPath = await fixture.writeManifest({
    operations: [
      {
        type: "replace-bytes",
        target: { component: "arm9", relativeOffset: 4 },
        expected: "a9a9",
        replacement: "0102",
      },
      {
        type: "replace-bytes",
        target: { component: "arm7", relativeOffset: 8 },
        expected: "a7a7",
        replacement: "0304",
      },
    ],
  });
  const loaded = await loadNdsMutationManifest(fixture.directory, manifestPath);
  const plan = await compileNdsMutationPlan(fixture.map, fixture.directory, loaded);

  assert.equal(plan.sourceSha256, fixture.sourceSha256);
  assert.equal(plan.operations.length, 2);
  assert.equal(plan.applicationOperations.length, 2);
  assert.match(plan.buildId, /^[0-9a-f]{64}$/u);
  assert.equal(plan.outputFilename, "test-mod.nds");
  assert.equal(JSON.stringify(serializeResolvedNdsMutationPlan(plan)).includes(fixture.directory), false);
});

test("rejects any physical overlap, including identical overlap", async () => {
  const fixture = await createMutationFixture();
  const manifestPath = await fixture.writeManifest({
    operations: [
      {
        type: "replace-bytes",
        target: { component: "arm9", relativeOffset: 4 },
        expected: "a9a9",
        replacement: "0102",
      },
      {
        type: "replace-bytes",
        target: { component: "arm9", relativeOffset: 5 },
        expected: "a9a9",
        replacement: "0304",
      },
    ],
  });
  const loaded = await loadNdsMutationManifest(fixture.directory, manifestPath);
  await assert.rejects(
    compileNdsMutationPlan(fixture.map, fixture.directory, loaded),
    (error: unknown) => error instanceof NdsError && error.category === "mutation-overlap",
  );
});

test("allows adjacent physical mutation ranges", async () => {
  const fixture = await createMutationFixture();
  const manifestPath = await fixture.writeManifest({
    operations: [
      {
        type: "replace-bytes",
        target: { component: "arm9", relativeOffset: 4 },
        expected: "a9a9",
        replacement: "0102",
      },
      {
        type: "replace-bytes",
        target: { component: "arm9", relativeOffset: 6 },
        expected: "a9a9",
        replacement: "0304",
      },
    ],
  });
  const loaded = await loadNdsMutationManifest(fixture.directory, manifestPath);
  await assert.doesNotReject(
    compileNdsMutationPlan(fixture.map, fixture.directory, loaded),
  );
});

test("rejects physical aliases even when canonical selectors differ", async () => {
  const fixture = await createMutationFixture();
  const overlay = fixture.map.overlays.arm9.find(
    (candidate) => candidate.overlayId === fixture.uncompressedOverlayId,
  );
  assert.ok(overlay);
  const source = (await readFile(fixture.romPath)).subarray(
    overlay.romOffset,
    overlay.romOffset + overlay.romSize,
  );
  const replacementA = await fixture.writeArtifact(
    "artifacts/overlay-a.bin",
    Buffer.alloc(source.length, 0x31),
  );
  const replacementB = await fixture.writeArtifact(
    "artifacts/overlay-b.bin",
    Buffer.alloc(source.length, 0x32),
  );
  const sourceHash = sha256(source);
  const manifestPath = await fixture.writeManifest({
    operations: [
      {
        type: "replace-component",
        target: { component: "arm9-overlay", overlayId: fixture.uncompressedOverlayId },
        expectedOriginalSha256: sourceHash,
        replacement: { artifact: replacementA.relativePath, sha256: replacementA.sha256 },
      },
      {
        type: "replace-component",
        target: { component: "nitrofs-file", fileId: fixture.uncompressedFileId },
        expectedOriginalSha256: sourceHash,
        replacement: { artifact: replacementB.relativePath, sha256: replacementB.sha256 },
      },
    ],
  });
  const loaded = await loadNdsMutationManifest(fixture.directory, manifestPath);
  await assert.rejects(
    compileNdsMutationPlan(fixture.map, fixture.directory, loaded),
    (error: unknown) => error instanceof NdsError && error.category === "mutation-overlap",
  );
});

test("fails closed when the manifest source identity differs from the canonical ROM", async () => {
  const fixture = await createMutationFixture();
  const manifestPath = await fixture.writeManifest({ sourceSha256: "0".repeat(64) });
  const loaded = await loadNdsMutationManifest(fixture.directory, manifestPath);
  await assert.rejects(
    compileNdsMutationPlan(fixture.map, fixture.directory, loaded),
    (error: unknown) => error instanceof NdsError && error.category === "source-rom-mismatch",
  );
});

test("normalization makes build identity stable across source operation order", async () => {
  const fixture = await createMutationFixture();
  const first = {
    type: "replace-bytes" as const,
    target: { component: "arm9" as const, relativeOffset: 4 },
    expected: "a9a9",
    replacement: "0102",
  };
  const second = {
    type: "replace-bytes" as const,
    target: { component: "arm7" as const, relativeOffset: 8 },
    expected: "a7a7",
    replacement: "0304",
  };
  const aPath = await fixture.writeManifest({ operations: [first, second] }, "plans/a.json");
  const bPath = await fixture.writeManifest({ operations: [second, first] }, "plans/b.json");
  const a = await loadNdsMutationManifest(fixture.directory, aPath);
  const b = await loadNdsMutationManifest(fixture.directory, bPath);
  const planA = await compileNdsMutationPlan(fixture.map, fixture.directory, a);
  const planB = await compileNdsMutationPlan(fixture.map, fixture.directory, b);

  assert.equal(a.sha256, b.sha256);
  assert.equal(planA.buildId, planB.buildId);
  assert.deepEqual(
    planA.operations.map((operation) => operation.index),
    planB.operations.map((operation) => operation.index),
  );
});
