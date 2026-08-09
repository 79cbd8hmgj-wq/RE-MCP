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

test("rejects uppercase source hashes and no-op byte operations", async () => {
  const fixture = await createMutationFixture();
  const uppercasePath = await fixture.writeManifest({
    sourceSha256: fixture.sourceSha256.toUpperCase(),
  }, "plans/uppercase.json");
  await rejectsAsManifestInvalid(
    loadNdsMutationManifest(fixture.directory, uppercasePath),
  );

  const noOpPath = await fixture.writeManifest({
    expected: "a9a9",
    replacement: "A9A9",
  }, "plans/no-op.json");
  await rejectsAsManifestInvalid(
    loadNdsMutationManifest(fixture.directory, noOpPath),
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

test("normalizes operation order deterministically", async () => {
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

  assert.equal(loadedA.canonicalJson, loadedB.canonicalJson);
  assert.equal(loadedA.sha256, loadedB.sha256);
});

test("rejects manifest paths that escape the workspace", async () => {
  const fixture = await createMutationFixture();
  await rejectsAsManifestInvalid(
    loadNdsMutationManifest(fixture.directory, "../mutation.json"),
  );
});
