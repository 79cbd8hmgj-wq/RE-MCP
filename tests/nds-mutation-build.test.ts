import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

import { hashFileSha256 } from "../src/services/nds/io.js";
import {
  buildNdsMutation,
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
