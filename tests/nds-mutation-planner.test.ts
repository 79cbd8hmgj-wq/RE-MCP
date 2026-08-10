import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { NdsError } from "../src/services/nds/errors.js";
import {
  loadNdsMutationManifest,
  serializeCanonicalJson,
} from "../src/services/nds/mutation/manifest.js";
import {
  compileNdsMutationPlan,
  serializeResolvedNdsMutationPlan,
} from "../src/services/nds/mutation/planner.js";
import { createMutationFixture } from "./helpers/nds-mutation-fixture.js";

function sha256(bytes: Buffer): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function sha256Text(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
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

test("uses the exact canonical build-identity JSON contract", async () => {
  const fixture = await createMutationFixture();
  const component = fixture.map.header.arm7;
  const source = (await readFile(fixture.romPath)).subarray(
    component.romOffset,
    component.romEnd,
  );
  const artifact = await fixture.writeArtifact(
    "artifacts/identity-arm7.bin",
    Buffer.alloc(source.length, 0x2f),
  );
  const manifestPath = await fixture.writeManifest({
    operations: [{
      type: "replace-component",
      target: { component: "arm7" },
      expectedOriginalSha256: sha256(source),
      replacement: { artifact: artifact.relativePath, sha256: artifact.sha256 },
    }],
  }, "plans/identity.json");
  const loaded = await loadNdsMutationManifest(fixture.directory, manifestPath);
  const plan = await compileNdsMutationPlan(fixture.map, fixture.directory, loaded);
  const canonicalIdentity = serializeCanonicalJson({
    format: "re-mcp-nds-build-identity",
    formatVersion: 1,
    sourceSha256: fixture.sourceSha256,
    manifestSha256: loaded.sha256,
    replacementArtifactSha256: [artifact.sha256],
  });
  assert.equal(plan.buildId, sha256Text(canonicalIdentity));
});

test("freezes the literal v1 resolved-plan and build identity", async () => {
  const fixture = await createMutationFixture();
  const manifestPath = await fixture.writeManifest({}, "plans/v1-freeze.json");
  const loaded = await loadNdsMutationManifest(fixture.directory, manifestPath);
  const plan = await compileNdsMutationPlan(fixture.map, fixture.directory, loaded);
  assert.fail(`V1_FREEZE=${JSON.stringify({
    manifestSha256: loaded.sha256,
    buildId: plan.buildId,
    serialized: serializeResolvedNdsMutationPlan(plan),
  })}`);
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

test("rejects physical aliases even when ordinary NitroFS selectors differ", async () => {
  const fixture = await createMutationFixture();
  const file = fixture.map.filesystem.files.find(
    (candidate) => candidate.fileId === fixture.ordinaryFileId,
  );
  assert.ok(file);
  const source = (await readFile(fixture.romPath)).subarray(file.startOffset, file.endOffset);
  const replacementA = await fixture.writeArtifact(
    "artifacts/asset-a.bin",
    Buffer.alloc(source.length, 0x31),
  );
  const replacementB = await fixture.writeArtifact(
    "artifacts/asset-b.bin",
    Buffer.alloc(source.length, 0x32),
  );
  const sourceHash = sha256(source);
  const manifestPath = await fixture.writeManifest({
    operations: [
      {
        type: "replace-component",
        target: { component: "nitrofs-file", fileId: fixture.ordinaryFileId },
        expectedOriginalSha256: sourceHash,
        replacement: { artifact: replacementA.relativePath, sha256: replacementA.sha256 },
      },
      {
        type: "replace-component",
        target: { component: "nitrofs-path", filePath: "asset.bin" },
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

test("preserves semantic manifest operation order and therefore build identity", async () => {
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

  assert.notEqual(a.sha256, b.sha256);
  assert.notEqual(planA.buildId, planB.buildId);
  assert.equal(planA.operations[0]?.component.component, "arm9");
  assert.equal(planB.operations[0]?.component.component, "arm7");
  assert.deepEqual(
    planA.applicationOperations.map((operation) => operation.component.component),
    planB.applicationOperations.map((operation) => operation.component.component),
  );
});

test("rejects replacement artifacts that alias the mutation manifest", async () => {
  const fixture = await createMutationFixture();
  const component = fixture.map.header.arm7;
  const source = (await readFile(fixture.romPath)).subarray(
    component.romOffset,
    component.romEnd,
  );
  const manifestPath = await fixture.writeManifest({
    operations: [{
      type: "replace-component",
      target: { component: "arm7" },
      expectedOriginalSha256: sha256(source),
      replacement: {
        artifact: "plans/manifest-alias.json",
        sha256: "0".repeat(64),
      },
    }],
  }, "plans/manifest-alias.json");
  const loaded = await loadNdsMutationManifest(fixture.directory, manifestPath);
  await assert.rejects(
    compileNdsMutationPlan(fixture.map, fixture.directory, loaded),
    (error: unknown) => error instanceof NdsError
      && error.category === "unsupported-mutation-target",
  );
});
