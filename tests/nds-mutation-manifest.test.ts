import assert from "node:assert/strict";
import test from "node:test";

import { NdsError } from "../src/services/nds/errors.js";
import {
  loadNdsMutationManifest,
  serializeCanonicalMutationManifest,
} from "../src/services/nds/mutation/manifest.js";
import { createMutationFixture } from "./helpers/nds-mutation-fixture.js";

async function rejectsAsManifestInvalid(promise: Promise<unknown>): Promise<void> {
  await assert.rejects(
    promise,
    (error: unknown) => error instanceof NdsError
      && error.category === "mutation-manifest-invalid",
  );
}

test("loads and canonically normalizes one strict mutation manifest", async () => {
  const fixture = await createMutationFixture();
  const manifestPath = await fixture.writeManifest({
    expected: "A9A9",
    replacement: "CCDD",
  });

  const loaded = await loadNdsMutationManifest(fixture.directory, manifestPath);
  assert.equal(loaded.manifest.operations[0]?.type, "replace-bytes");
  assert.match(loaded.sha256, /^[0-9a-f]{64}$/u);
  assert.equal(loaded.canonicalJson, serializeCanonicalMutationManifest(loaded.manifest));
  assert.match(loaded.canonicalJson, /"expected":"a9a9"/u);
  assert.match(loaded.canonicalJson, /"replacement":"ccdd"/u);
  assert.equal(loaded.workspaceRelativePath, "plans/mutation.json");
});

test("rejects uppercase source hashes as invalid manifests", async () => {
  const fixture = await createMutationFixture();
  const uppercasePath = await fixture.writeManifest({
    sourceSha256: fixture.sourceSha256.toUpperCase(),
  }, "plans/uppercase.json");
  await rejectsAsManifestInvalid(
    loadNdsMutationManifest(fixture.directory, uppercasePath),
  );
});

test("rejects byte-operation no-ops with the dedicated mutation category", async () => {
  const fixture = await createMutationFixture();
  const noOpPath = await fixture.writeManifest({
    expected: "a9a9",
    replacement: "A9A9",
  }, "plans/no-op.json");
  await assert.rejects(
    loadNdsMutationManifest(fixture.directory, noOpPath),
    (error: unknown) => error instanceof NdsError
      && error.category === "mutation-no-op",
  );
});

test("rejects unknown fields and invalid output filenames", async () => {
  const fixture = await createMutationFixture();
  const unknownPath = await fixture.writeManifest({
    extraRoot: { surprise: true },
  }, "plans/unknown.json");
  await rejectsAsManifestInvalid(
    loadNdsMutationManifest(fixture.directory, unknownPath),
  );

  const outputPath = await fixture.writeManifest({
    outputFilename: "../escaped.nds",
  }, "plans/output.json");
  await rejectsAsManifestInvalid(
    loadNdsMutationManifest(fixture.directory, outputPath),
  );
});

test("rejects malformed byte hex and mismatched byte lengths", async () => {
  const fixture = await createMutationFixture();
  const malformedPath = await fixture.writeManifest({
    expected: "xyz1",
  }, "plans/malformed.json");
  await rejectsAsManifestInvalid(
    loadNdsMutationManifest(fixture.directory, malformedPath),
  );

  const lengthPath = await fixture.writeManifest({
    expected: "a9a9",
    replacement: "cc",
  }, "plans/length.json");
  await rejectsAsManifestInvalid(
    loadNdsMutationManifest(fixture.directory, lengthPath),
  );
});

test("requires portable workspace-relative replacement artifact paths", async () => {
  const fixture = await createMutationFixture();
  const operation = {
    type: "replace-component" as const,
    target: { component: "arm9" },
    expectedOriginalSha256: "0".repeat(64),
    replacement: {
      artifact: "../outside.bin",
      sha256: "1".repeat(64),
    },
  };
  const manifestPath = await fixture.writeManifest({
    operations: [operation],
  }, "plans/artifact.json");
  await rejectsAsManifestInvalid(
    loadNdsMutationManifest(fixture.directory, manifestPath),
  );
});

test("canonical JSON preserves semantic operation order", async () => {
  const fixture = await createMutationFixture();
  const first = {
    type: "replace-bytes" as const,
    target: { component: "arm7", relativeOffset: 2 },
    expected: "a7a7",
    replacement: "0102",
  };
  const second = {
    type: "replace-bytes" as const,
    target: { component: "arm9", relativeOffset: 4 },
    expected: "a9a9",
    replacement: "0304",
  };

  const pathA = await fixture.writeManifest({
    operations: [first, second],
  }, "plans/a.json");
  const pathB = await fixture.writeManifest({
    operations: [second, first],
  }, "plans/b.json");
  const loadedA = await loadNdsMutationManifest(fixture.directory, pathA);
  const loadedB = await loadNdsMutationManifest(fixture.directory, pathB);

  assert.notEqual(loadedA.canonicalJson, loadedB.canonicalJson);
  assert.notEqual(loadedA.sha256, loadedB.sha256);
  assert.equal(loadedA.manifest.operations[0]?.target.component, "arm7");
  assert.equal(loadedB.manifest.operations[0]?.target.component, "arm9");
});

test("rejects manifest paths that escape the workspace", async () => {
  const fixture = await createMutationFixture();
  await rejectsAsManifestInvalid(
    loadNdsMutationManifest(fixture.directory, "../mutation.json"),
  );
});
