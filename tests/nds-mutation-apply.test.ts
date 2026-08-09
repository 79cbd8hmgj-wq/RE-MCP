import assert from "node:assert/strict";
import { open, readFile, readdir, stat } from "node:fs/promises";
import type { FileHandle } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

import { hashFileSha256 } from "../src/services/nds/io.js";
import { applyNdsMutationPlan, type NdsMutationApplyIo } from "../src/services/nds/mutation/apply.js";
import { loadNdsMutationManifest } from "../src/services/nds/mutation/manifest.js";
import { compileNdsMutationPlan } from "../src/services/nds/mutation/planner.js";
import {
  cleanupNdsMutationStage,
  createNdsMutationStage,
} from "../src/services/nds/mutation/staging.js";
import { createMutationFixture } from "./helpers/nds-mutation-fixture.js";

async function oneBytePlan() {
  const fixture = await createMutationFixture();
  const expected = (await readFile(fixture.romPath))
    .subarray(fixture.arm9Offset, fixture.arm9Offset + 2)
    .toString("hex");
  const replacement = expected === "1234" ? "5678" : "1234";
  const manifestPath = await fixture.writeManifest({
    outputFilename: "apply-test.nds",
    operations: [{
      type: "replace-bytes",
      target: { component: "arm9", relativeOffset: 0 },
      expected,
      replacement,
    }],
  });
  const loaded = await loadNdsMutationManifest(fixture.directory, manifestPath);
  const plan = await compileNdsMutationPlan(fixture.map, fixture.directory, loaded);
  return { fixture, plan, replacement };
}

test("stages an exact source copy and mutates only the staged ROM", async () => {
  const { fixture, plan, replacement } = await oneBytePlan();
  const sourceBefore = await hashFileSha256(fixture.romPath);
  const stage = await createNdsMutationStage(plan, fixture.directory);
  try {
    assert.equal(await hashFileSha256(stage.stagedRomPath), sourceBefore);
    assert.equal(path.basename(stage.stagedRomPath), "apply-test.nds");
    assert.notEqual(path.resolve(stage.stagedRomPath), path.resolve(fixture.romPath));

    await applyNdsMutationPlan(plan, stage);

    assert.equal(await hashFileSha256(fixture.romPath), sourceBefore);
    assert.notEqual(await hashFileSha256(stage.stagedRomPath), sourceBefore);
    assert.equal((await stat(stage.stagedRomPath)).size, plan.sourceSize);
    const staged = await readFile(stage.stagedRomPath);
    assert.equal(
      staged.subarray(fixture.arm9Offset, fixture.arm9Offset + 2).toString("hex"),
      replacement,
    );
  } finally {
    await cleanupNdsMutationStage(stage);
  }
});

test("applies multiple disjoint writes and a whole-component artifact", async () => {
  const fixture = await createMutationFixture();
  const source = await readFile(fixture.romPath);
  const arm7 = fixture.map.header.arm7;
  const arm7Source = source.subarray(arm7.romOffset, arm7.romEnd);
  const arm7Replacement = Buffer.alloc(arm7Source.length, 0x3c);
  const artifact = await fixture.writeArtifact("artifacts/arm7-apply.bin", arm7Replacement);
  const manifestPath = await fixture.writeManifest({
    outputFilename: "multi.nds",
    operations: [
      {
        type: "replace-bytes",
        target: { component: "arm9", relativeOffset: 0 },
        expected: source.subarray(fixture.arm9Offset, fixture.arm9Offset + 2).toString("hex"),
        replacement: "1234",
      },
      {
        type: "replace-bytes",
        target: { component: "nitrofs-file", fileId: fixture.ordinaryFileId, relativeOffset: 2 },
        expected: source.subarray(fixture.ordinaryRomOffset + 2, fixture.ordinaryRomOffset + 4).toString("hex"),
        replacement: "beef",
      },
      {
        type: "replace-component",
        target: { component: "arm7" },
        expectedOriginalSha256: fixture.map.header.arm7.size === arm7Source.length
          ? await hashFileSha256(await (async () => {
            const temp = await fixture.writeArtifact("artifacts/arm7-source.bin", arm7Source);
            return temp.absolutePath;
          })())
          : "0".repeat(64),
        replacement: { artifact: artifact.relativePath, sha256: artifact.sha256 },
      },
    ],
  });
  const loaded = await loadNdsMutationManifest(fixture.directory, manifestPath);
  const plan = await compileNdsMutationPlan(fixture.map, fixture.directory, loaded);
  const stage = await createNdsMutationStage(plan, fixture.directory);
  try {
    await applyNdsMutationPlan(plan, stage);
    const staged = await readFile(stage.stagedRomPath);
    assert.equal(staged.subarray(fixture.arm9Offset, fixture.arm9Offset + 2).toString("hex"), "1234");
    assert.equal(staged.subarray(fixture.ordinaryRomOffset + 2, fixture.ordinaryRomOffset + 4).toString("hex"), "beef");
    assert.deepEqual(staged.subarray(arm7.romOffset, arm7.romEnd), arm7Replacement);
  } finally {
    await cleanupNdsMutationStage(stage);
  }
});

test("an injected second staged write failure never changes the source ROM", async () => {
  const fixture = await createMutationFixture();
  const source = await readFile(fixture.romPath);
  const manifestPath = await fixture.writeManifest({
    outputFilename: "failure.nds",
    operations: [
      {
        type: "replace-bytes",
        target: { component: "arm9", relativeOffset: 0 },
        expected: source.subarray(fixture.arm9Offset, fixture.arm9Offset + 2).toString("hex"),
        replacement: "1234",
      },
      {
        type: "replace-bytes",
        target: { component: "arm9", relativeOffset: 4 },
        expected: source.subarray(fixture.arm9Offset + 4, fixture.arm9Offset + 6).toString("hex"),
        replacement: "5678",
      },
    ],
  });
  const loaded = await loadNdsMutationManifest(fixture.directory, manifestPath);
  const plan = await compileNdsMutationPlan(fixture.map, fixture.directory, loaded);
  const sourceBefore = await hashFileSha256(fixture.romPath);
  const stage = await createNdsMutationStage(plan, fixture.directory);
  let stagedWrites = 0;
  const io: NdsMutationApplyIo = {
    async open(filePath, flags) {
      const handle = await open(filePath, flags);
      if (flags !== "r+") {
        return handle;
      }
      return new Proxy(handle, {
        get(target, property, receiver) {
          if (property !== "write") {
            const value = Reflect.get(target, property, receiver) as unknown;
            return typeof value === "function" ? value.bind(target) : value;
          }
          return async (
            buffer: Uint8Array,
            offset: number,
            length: number,
            position: number,
          ) => {
            stagedWrites += 1;
            if (stagedWrites === 2) {
              throw new Error("injected second staged write failure");
            }
            return await target.write(buffer, offset, length, position);
          };
        },
      }) as FileHandle;
    },
  };

  try {
    await assert.rejects(
      applyNdsMutationPlan(plan, stage, io),
      /injected second staged write failure/u,
    );
    assert.equal(await hashFileSha256(fixture.romPath), sourceBefore);
  } finally {
    await cleanupNdsMutationStage(stage);
  }
});

test("keeps the staged write boundary confined to apply.ts", async () => {
  const mutationDirectory = path.join(process.cwd(), "src", "services", "nds", "mutation");
  const entries = (await readdir(mutationDirectory)).filter((entry) => entry.endsWith(".ts"));
  const files = await Promise.all(entries.map(async (entry) => ({
    entry,
    source: await readFile(path.join(mutationDirectory, entry), "utf8"),
  })));
  const rPlusOwners = files
    .filter(({ source }) => source.includes('"r+"'))
    .map(({ entry }) => entry)
    .sort();
  assert.deepEqual(rPlusOwners, ["apply.ts"]);
  for (const { source } of files) {
    assert.equal(/export\s+(?:async\s+)?function\s+\w+\s*\(\s*romOffset\s*,\s*bytes/u.test(source), false);
  }
});
