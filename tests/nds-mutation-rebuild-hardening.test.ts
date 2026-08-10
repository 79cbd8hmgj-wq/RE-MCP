import assert from "node:assert/strict";
import { readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import test, { type TestContext } from "node:test";

import { crc16NdsHeader } from "../src/services/nds/header-rebuild.js";
import { hashFileSha256 } from "../src/services/nds/io.js";
import { buildNdsMutation, verifyPublishedNdsMutationBuild } from "../src/services/nds/mutation/build.js";
import { loadNdsMutationManifest } from "../src/services/nds/mutation/manifest.js";
import { readNdsRomMap } from "../src/services/nds/rom-map.js";
import { NdsError } from "../src/services/nds/errors.js";
import { createMutationFixture } from "./helpers/nds-mutation-fixture.js";

async function buildTwoArm9Edits(t: TestContext) {
  const fixture = await createMutationFixture();
  t.after(async () => {
    await rm(fixture.directory, { recursive: true, force: true });
  });

  const source = await readFile(fixture.romPath);
  // The generic fixture advertises a 32 MiB cartridge capacity. This release
  // test needs only the smallest valid capacity, so keep its staged output
  // bounded instead of consuming 32 MiB twice just to test evidence behavior.
  source.writeUInt8(0, 0x14);
  source.writeUInt16LE(crc16NdsHeader(source.subarray(0, 0x15e)), 0x15e);
  await writeFile(fixture.romPath, source);
  const map = await readNdsRomMap(fixture.romPath);
  const sourceSha256 = await hashFileSha256(fixture.romPath);

  const manifestPath = await fixture.writeManifest({
    formatVersion: 2,
    sourceSha256,
    outputFilename: "rebuild-hardening.nds",
    operations: [
      {
        type: "replace-bytes",
        target: { component: "arm9", relativeOffset: 4 },
        expected: "a9a9",
        replacement: "0102",
      },
      {
        type: "replace-bytes",
        target: { component: "arm9", relativeOffset: 8 },
        expected: "a9a9",
        replacement: "0304",
      },
    ],
  }, "plans/rebuild-hardening.json");
  const loaded = await loadNdsMutationManifest(fixture.directory, manifestPath);
  const result = await buildNdsMutation(map, fixture.directory, loaded);
  return { fixture, map, loaded, result };
}

test("v2 changed-components consolidates multiple operations on one physical component", async (t) => {
  const built = await buildTwoArm9Edits(t);
  const report = JSON.parse(
    await readFile(path.join(built.result.outputRoot, "changed-components.json"), "utf8"),
  ) as {
    components: Array<{
      component: string;
      romStart: number;
      romEnd: number;
      operationIndexes: number[];
    }>;
  };

  assert.equal(report.components.length, 1);
  assert.equal(report.components[0]?.component, "arm9");
  assert.equal(report.components[0]?.romStart, built.map.header.arm9.romOffset);
  assert.equal(report.components[0]?.romEnd, built.map.header.arm9.romOffset + built.map.header.arm9.size);
  assert.deepEqual(report.components[0]?.operationIndexes, [0, 1]);

  const verification = JSON.parse(
    await readFile(path.join(built.result.outputRoot, "verification.json"), "utf8"),
  ) as { changedComponentCount: number };
  assert.equal(verification.changedComponentCount, 1);
});

test("tampered v2 deterministic output still fails closed without repair", async (t) => {
  const built = await buildTwoArm9Edits(t);
  const before = await readFile(built.result.outputRomPath);
  const tampered = Buffer.from(before);
  tampered[tampered.length - 1] = (tampered[tampered.length - 1] ?? 0) ^ 0xff;
  await writeFile(built.result.outputRomPath, tampered);
  const tamperedSha256 = await hashFileSha256(built.result.outputRomPath);

  await assert.rejects(
    verifyPublishedNdsMutationBuild(
      built.map,
      built.fixture.directory,
      built.loaded,
    ),
    (error: unknown) => error instanceof NdsError && error.category === "publish-collision",
  );
  assert.equal(await hashFileSha256(built.result.outputRomPath), tamperedSha256);
});
