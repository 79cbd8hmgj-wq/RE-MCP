import assert from "node:assert/strict";
import test from "node:test";

import { NdsError } from "../src/services/nds/errors.js";
import { loadNdsMutationManifest } from "../src/services/nds/mutation/manifest.js";
import { createMutationFixture } from "./helpers/nds-mutation-fixture.js";

async function rejectsManifest(
  fixture: Awaited<ReturnType<typeof createMutationFixture>>,
  operations: readonly Record<string, unknown>[],
  relativePath: string,
): Promise<void> {
  const path = await fixture.writeManifest({
    formatVersion: 2,
    operations: operations as never,
  }, relativePath);
  await assert.rejects(
    loadNdsMutationManifest(fixture.directory, path),
    (error: unknown) => error instanceof NdsError
      && error.category === "mutation-manifest-invalid",
  );
}

test("keeps the frozen v1 canonical manifest identity unchanged", async () => {
  const fixture = await createMutationFixture();
  const manifestPath = await fixture.writeManifest({
    sourceSha256: "0".repeat(64),
    outputFilename: "frozen.nds",
    operations: [{
      type: "replace-bytes",
      target: { component: "arm9", relativeOffset: 4 },
      expected: "a9a9",
      replacement: "1234",
    }],
  }, "plans/frozen-v1.json");
  const loaded = await loadNdsMutationManifest(fixture.directory, manifestPath);
  assert.equal(
    loaded.canonicalJson,
    '{"format":"re-mcp-nds-mutation","formatVersion":1,"operations":[{"expected":"a9a9","replacement":"1234","target":{"component":"arm9","relativeOffset":4},"type":"replace-bytes"}],"output":{"filename":"frozen.nds"},"source":{"sha256":"0000000000000000000000000000000000000000000000000000000000000000"}}',
  );
  assert.equal(
    loaded.sha256,
    "73505d3f0747daa72d5498e857ba7d54c2b2973e013a6b7a3ac4846ffbf7440a",
  );
});

test("loads and normalizes all manifest v2 operation classes", async () => {
  const fixture = await createMutationFixture();
  const manifestPath = await fixture.writeManifest({
    formatVersion: 2,
    operations: [
      {
        type: "replace-nitrofs-file",
        target: { fileId: 0 },
        expectedOriginalSha256: "a".repeat(64),
        replacement: { artifact: "patches/file.bin", sha256: "b".repeat(64) },
      },
      {
        type: "add-nitrofs-file",
        path: "re_mcp/attributes/i2dt.bin",
        replacement: { artifact: "patches/i2dt.bin", sha256: "c".repeat(64) },
      },
      {
        type: "replace-decoded-overlay",
        target: { processor: "arm9", overlayId: 7 },
        expectedStoredSha256: "d".repeat(64),
        expectedRuntimeSha256: "e".repeat(64),
        replacement: { artifact: "patches/overlay7-runtime.bin", sha256: "f".repeat(64) },
      },
    ],
  }, "plans/v2.json");

  const loaded = await loadNdsMutationManifest(fixture.directory, manifestPath);
  assert.equal(loaded.manifest.formatVersion, 2);
  assert.deepEqual(
    loaded.manifest.operations.map((operation) => operation.type),
    ["replace-nitrofs-file", "add-nitrofs-file", "replace-decoded-overlay"],
  );
  assert.match(loaded.canonicalJson, /"path":"re_mcp\/attributes\/i2dt.bin"/u);
});

test("manifest v2 rejects caller-selected IDs, offsets, and compression controls", async () => {
  const fixture = await createMutationFixture();
  await rejectsManifest(fixture, [{
    type: "add-nitrofs-file",
    path: "re_mcp/a.bin",
    fileId: 99,
    replacement: { artifact: "patches/a.bin", sha256: "a".repeat(64) },
  }], "plans/id.json");
  await rejectsManifest(fixture, [{
    type: "replace-nitrofs-file",
    target: { fileId: 0 },
    expectedOriginalSha256: "a".repeat(64),
    outputOffset: 123,
    replacement: { artifact: "patches/a.bin", sha256: "b".repeat(64) },
  }], "plans/offset.json");
  await rejectsManifest(fixture, [{
    type: "replace-decoded-overlay",
    target: { processor: "arm9", overlayId: 7 },
    expectedStoredSha256: "a".repeat(64),
    expectedRuntimeSha256: "b".repeat(64),
    compressedSize: 123,
    replacement: { artifact: "patches/a.bin", sha256: "c".repeat(64) },
  }], "plans/compression.json");
});

test("manifest v2 rejects ambiguous existing-file targets and invalid extension paths", async () => {
  const fixture = await createMutationFixture();
  await rejectsManifest(fixture, [{
    type: "replace-nitrofs-file",
    target: { fileId: 0, filePath: "asset.bin" },
    expectedOriginalSha256: "a".repeat(64),
    replacement: { artifact: "patches/a.bin", sha256: "b".repeat(64) },
  }], "plans/ambiguous.json");
  await rejectsManifest(fixture, [{
    type: "add-nitrofs-file",
    path: "re_mcp/../evil.bin",
    replacement: { artifact: "patches/a.bin", sha256: "b".repeat(64) },
  }], "plans/traversal.json");
});

test("manifest v1 rejects v2-only operations", async () => {
  const fixture = await createMutationFixture();
  const manifestPath = await fixture.writeManifest({
    formatVersion: 1,
    operations: [{
      type: "add-nitrofs-file",
      path: "re_mcp/a.bin",
      replacement: { artifact: "patches/a.bin", sha256: "a".repeat(64) },
    }],
  }, "plans/v1-v2-operation.json");
  await assert.rejects(
    loadNdsMutationManifest(fixture.directory, manifestPath),
    (error: unknown) => error instanceof NdsError
      && error.category === "mutation-manifest-invalid",
  );
});
