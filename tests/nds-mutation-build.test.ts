import assert from "node:assert/strict";
import { open, readFile, readdir, writeFile } from "node:fs/promises";
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

async function overwriteByte(filePath: string, offset: number, value: number): Promise<void> {
  const handle = await open(filePath, "r+");
  try {
    await handle.write(Buffer.from([value]), 0, 1, offset);
    await handle.sync();
  } finally {
    await handle.close();
  }
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

test("verification evidence explicitly records lineage, counts, parse proof, and operation proof", async () => {
  const { fixture, loaded, result } = await buildFixture();
  const report = JSON.parse(
    await readFile(path.join(result.outputRoot, "verification.json"), "utf8"),
  ) as {
    status: string;
    source: { rom: string; sha256: string; size: number; unchanged: boolean };
    output: { rom: string; sha256: string; size: number };
    manifestSha256: string;
    buildId: string;
    operationCount: number;
    changedComponentCount: number;
    changedByteCount: number;
    structuralMetadataUnchanged: boolean;
    structuralMapUnchanged: boolean;
    canonicalOutputParse: string;
    unexpectedChangedBytes: number;
    operations: Array<{
      index: number;
      status: string;
      target: { component: string };
      romStart: number;
      romEnd: number;
      guard: { expected: string };
      replacement: { bytes: string };
    }>;
  };

  assert.equal(report.status, "passed");
  assert.equal(report.source.rom, fixture.map.romPath.split(path.sep).pop());
  assert.equal(report.source.sha256, fixture.sourceSha256);
  assert.equal(report.source.size, fixture.map.fileSize);
  assert.equal(report.source.unchanged, true);
  assert.equal(
    report.output.rom,
    `output/nds/${fixture.map.sha256Prefix}/${result.buildId}/published.nds`,
  );
  assert.equal(report.output.sha256, result.outputSha256);
  assert.equal(report.output.size, fixture.map.fileSize);
  assert.equal(report.manifestSha256, loaded.sha256);
  assert.equal(report.buildId, result.buildId);
  assert.equal(report.operationCount, 1);
  assert.equal(report.changedComponentCount, 1);
  assert.ok(report.changedByteCount > 0);
  assert.equal(report.structuralMetadataUnchanged, true);
  assert.equal(report.structuralMapUnchanged, true);
  assert.equal(report.canonicalOutputParse, "passed");
  assert.equal(report.unexpectedChangedBytes, 0);
  assert.equal(report.operations[0]?.index, 0);
  assert.equal(report.operations[0]?.status, "passed");
  assert.equal(report.operations[0]?.target.component, "arm9");
  assert.equal(report.operations[0]?.romStart, fixture.arm9Offset);
  assert.equal(report.operations[0]?.romEnd, fixture.arm9Offset + 2);
  assert.equal(report.operations[0]?.guard.expected, "a9a9");
  assert.equal(report.operations[0]?.replacement.bytes, "1234");
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

test("changed-components deduplicates one physical NitroFS file across ID and path selectors", async () => {
  const fixture = await createMutationFixture();
  const source = await readFile(fixture.romPath);
  const relative = await fixture.writeManifest({
    outputFilename: "dedupe.nds",
    operations: [
      {
        type: "replace-bytes",
        target: {
          component: "nitrofs-file",
          fileId: fixture.ordinaryFileId,
          relativeOffset: 0,
        },
        expected: source.subarray(
          fixture.ordinaryRomOffset,
          fixture.ordinaryRomOffset + 2,
        ).toString("hex"),
        replacement: "1234",
      },
      {
        type: "replace-bytes",
        target: {
          component: "nitrofs-path",
          filePath: "asset.bin",
          relativeOffset: 4,
        },
        expected: source.subarray(
          fixture.ordinaryRomOffset + 4,
          fixture.ordinaryRomOffset + 6,
        ).toString("hex"),
        replacement: "5678",
      },
    ],
  });
  const loaded = await loadNdsMutationManifest(fixture.directory, relative);
  const result = await buildNdsMutation(fixture.map, fixture.directory, loaded);
  const report = JSON.parse(
    await readFile(path.join(result.outputRoot, "changed-components.json"), "utf8"),
  ) as {
    components: Array<{
      component: string;
      fileId: number | null;
      filePath: string | null;
      operationIndexes: number[];
    }>;
  };

  assert.equal(report.components.length, 1);
  assert.equal(report.components[0]?.component, "nitrofs-file");
  assert.equal(report.components[0]?.fileId, fixture.ordinaryFileId);
  assert.equal(report.components[0]?.filePath, "asset.bin");
  assert.deepEqual(report.components[0]?.operationIndexes, [0, 1]);
});

test("rejects a staged ROM that changes after verification but before publication", async () => {
  const fixture = await createMutationFixture();
  const loaded = await loadByteManifest(fixture);
  let stagedPath: string | null = null;
  await assert.rejects(
    buildNdsMutation(
      fixture.map,
      fixture.directory,
      loaded,
      {
        async beforePublish(stage) {
          stagedPath = stage.stagedRomPath;
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
  assert.notEqual(stagedPath, null);
  const outputParent = path.join(
    fixture.directory,
    "output",
    "nds",
    fixture.map.sha256Prefix,
  );
  const entries = await readdir(outputParent);
  assert.equal(entries.some((entry) => !entry.startsWith(".")), false);
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
