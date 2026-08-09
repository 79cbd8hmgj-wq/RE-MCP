import assert from "node:assert/strict";
import test from "node:test";

import { planNdsFilesystemExtensions } from "../src/services/nds/mutation/filesystem-plan.js";
import type { NdsAddNitroFsFileOperation } from "../src/services/nds/mutation/manifest.js";
import { createMutationFixture } from "./helpers/nds-mutation-fixture.js";

async function addition(
  fixture: Awaited<ReturnType<typeof createMutationFixture>>,
  index: number,
  path: string,
): Promise<{ index: number; operation: NdsAddNitroFsFileOperation }> {
  const artifact = await fixture.writeArtifact(
    `patches/preorder-${index}.bin`,
    Buffer.from([0x40 + index]),
  );
  return {
    index,
    operation: {
      type: "add-nitrofs-file",
      path,
      replacement: {
        artifact: artifact.relativePath,
        sha256: artifact.sha256,
      },
    },
  };
}

test("assigns new directory IDs by lexicographic tree preorder, not flat string order", async () => {
  const fixture = await createMutationFixture();
  const nested = await addition(fixture, 0, "a/child/deep.bin");
  const sibling = await addition(fixture, 1, "a-b/shallow.bin");

  const plan = await planNdsFilesystemExtensions(
    fixture.map,
    fixture.directory,
    [sibling, nested],
  );

  assert.deepEqual(
    plan.addedDirectories.map(({ path, directoryId }) => [path, directoryId]),
    [
      ["a", 0xf001],
      ["a/child", 0xf002],
      ["a-b", 0xf003],
    ],
  );
  assert.deepEqual(
    plan.addedFiles.map(({ path, fileId }) => [path, fileId]),
    [
      ["a/child/deep.bin", fixture.map.fat.length],
      ["a-b/shallow.bin", fixture.map.fat.length + 1],
    ],
  );
});
