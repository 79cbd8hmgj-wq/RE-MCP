import assert from "node:assert/strict";
import { readFile, readdir, writeFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

import { NdsError } from "../src/services/nds/errors.js";
import { hashFileSha256 } from "../src/services/nds/io.js";
import {
  buildNdsMutation,
  verifyPublishedNdsMutationBuild,
  type NdsMutationBuildResult,
} from "../src/services/nds/mutation/build.js";
import { loadNdsMutationManifest, type LoadedNdsMutationManifest } from "../src/services/nds/mutation/manifest.js";
import { createMutationFixture, type MutationFixture } from "./helpers/nds-mutation-fixture.js";

const EXPECTED_ENTRIES = [
  "changed-components.json",
  "mutation-manifest.json",
  "output.sha256",
  "published.nds",
  "resolved-plan.json",
  "verification.json",
] as const;

async function loadByteManifest(
  fixture: MutationFixture,
): Promise<LoadedNdsMutationManifest> {
  const source = await readFile(fixture.romPath);
  const relative = await fixture.writeManifest({
    outputFilename: "published.nds",
    operations: [{
      type: "replace-bytes",
      target: { component: "arm9", relativeOffset: 0 },
      expected: source.subarray(fixture.arm9Offset, fixture.arm9Offset + 2).toString("hex"),
      replacement: "1234",
    }],
  });
  return await loadNdsMutationManifest(fixture.directory, relative);
}

async function buildFixture(): Promise<{
  readonly fixture: MutationFixture;
  readonly loaded: LoadedNdsMutationManifest;
  readonly result: NdsMutationBuildResult;
}> {
  const fixture = await createMutationFixture();
  const loaded = await loadByteManifest(fixture);
  const result = await buildNdsMutation(fixture.map, fixture.directory, loaded);
  return { fixture, loaded, result };
}

function isPublishCollision(error: unknown): boolean {
  return error instanceof NdsError && error.category === "publish-collision";
}

test("publishes exactly one verified deterministic build directory", async () => {
  const fixture = await createMutationFixture();
  const loaded = await loadByteManifest(fixture);
  const sourceBefore = await hashFileSha256(fixture.romPath);
  const result = await buildNdsMutation(fixture.map, fixture.directory, loaded);

  assert.equal(result.reused, false);
  assert.equal(result.verification.status, "passed");
  assert.equal(result.verification.unexpectedChangedBytes, 0);
  assert.equal(await hashFileSha256(fixture.romPath), sourceBefore);
  assert.equal(result.outputSha256, await hashFileSha256(result.outputRomPath));
  assert.equal(path.dirname(result.outputRomPath), result.outputRoot);
  assert.deepEqual((await readdir(result.outputRoot)).sort(), [...EXPECTED_ENTRIES].sort());

  const parentEntries = await readdir(path.dirname(result.outputRoot));
  assert.equal(parentEntries.some((entry) => entry.startsWith(`.${result.buildId}.tmp-`)), false);
});

test("writes deterministic evidence without absolute workspace paths", async () => {
  const { fixture, result } = await buildFixture();
  for (const filename of [
    "mutation-manifest.json",
    "resolved-plan.json",
    "verification.json",
    "changed-components.json",
  ]) {
    const text = await readFile(path.join(result.outputRoot, filename), "utf8");
    assert.equal(text.includes(fixture.directory), false, `${filename} leaked an absolute workspace path`);
    assert.doesNotThrow(() => JSON.parse(text));
  }
  const checksum = await readFile(path.join(result.outputRoot, "output.sha256"), "utf8");
  assert.equal(checksum, `${result.outputSha256}  published.nds\n`);
});

test("identical inputs in different absolute workspaces produce byte-identical ROM and evidence", async () => {
  const firstFixture = await createMutationFixture();
  const secondFixture = await createMutationFixture();
  const firstLoaded = await loadByteManifest(firstFixture);
  const secondLoaded = await loadByteManifest(secondFixture);
  const first = await buildNdsMutation(firstFixture.map, firstFixture.directory, firstLoaded);
  const second = await buildNdsMutation(secondFixture.map, secondFixture.directory, secondLoaded);

  assert.equal(first.buildId, second.buildId);
  for (const filename of EXPECTED_ENTRIES) {
    const left = await readFile(path.join(first.outputRoot, filename));
    const right = await readFile(path.join(second.outputRoot, filename));
    assert.deepEqual(left, right, `${filename} differs across absolute workspaces`);
  }
});

test("reuses an exact deterministic build only after fresh revalidation", async () => {
  const { fixture, loaded, result: first } = await buildFixture();
  const second = await buildNdsMutation(fixture.map, fixture.directory, loaded);
  assert.equal(second.buildId, first.buildId);
  assert.equal(second.reused, true);
  assert.equal(second.outputSha256, first.outputSha256);
  assert.deepEqual(second.verification, first.verification);

  const verified = await verifyPublishedNdsMutationBuild(
    fixture.map,
    fixture.directory,
    loaded,
  );
  assert.equal(verified.reused, true);
  assert.equal(verified.buildId, first.buildId);
  assert.equal(verified.outputSha256, first.outputSha256);
});

test("tampered published ROM or evidence fails closed as publish-collision without repair", async (context) => {
  for (const filename of EXPECTED_ENTRIES) {
    await context.test(filename, async () => {
      const { fixture, loaded, result } = await buildFixture();
      const target = path.join(result.outputRoot, filename);
      const before = await readFile(target);
      const tampered = Buffer.from(before);
      if (filename === "published.nds") {
        tampered[fixture.unrelatedRomOffset] = (tampered[fixture.unrelatedRomOffset] ?? 0) ^ 0xff;
      } else {
        tampered[0] = (tampered[0] ?? 0) ^ 0x01;
      }
      await writeFile(target, tampered);
      const tamperedHash = await hashFileSha256(target);

      await assert.rejects(
        buildNdsMutation(fixture.map, fixture.directory, loaded),
        isPublishCollision,
      );
      assert.equal(await hashFileSha256(target), tamperedHash);

      await assert.rejects(
        verifyPublishedNdsMutationBuild(fixture.map, fixture.directory, loaded),
        isPublishCollision,
      );
      assert.equal(await hashFileSha256(target), tamperedHash);
      assert.deepEqual((await readdir(result.outputRoot)).sort(), [...EXPECTED_ENTRIES].sort());
    });
  }
});

test("unexpected or missing published entries fail closed", async () => {
  const extra = await buildFixture();
  await writeFile(path.join(extra.result.outputRoot, "unexpected.txt"), "unexpected\n");
  await assert.rejects(
    verifyPublishedNdsMutationBuild(extra.fixture.map, extra.fixture.directory, extra.loaded),
    isPublishCollision,
  );

  const missing = await buildFixture();
  await writeFile(path.join(missing.result.outputRoot, "verification.json"), Buffer.alloc(0));
  await assert.rejects(
    buildNdsMutation(missing.fixture.map, missing.fixture.directory, missing.loaded),
    isPublishCollision,
  );
});
