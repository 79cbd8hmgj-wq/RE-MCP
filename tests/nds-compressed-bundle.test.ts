import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

import { extractNdsAnalysisBundle } from "../src/services/nds/extraction.js";
import {
  COMPRESSED_ARM_CODE_STORED_OFFSET,
  createCompressedArmCodeFixture,
} from "./helpers/nds-compressed-code-fixture.js";

test("analysis bundle keeps stored compressed bytes separate from the decoded runtime artifact", async () => {
  const { fixture, map, overlayId, decoded, stored } = await createCompressedArmCodeFixture();
  const result = await extractNdsAnalysisBundle(map, fixture.directory);

  const storedPath = path.join(
    result.outputRoot,
    "overlays",
    "arm9",
    `overlay_${overlayId}.bin`,
  );
  const runtimePath = path.join(
    result.outputRoot,
    "runtime",
    "overlays",
    "arm9",
    `overlay_${overlayId}.bin`,
  );

  const storedArtifact = await readFile(storedPath);
  const runtimeArtifact = await readFile(runtimePath);
  assert.equal(storedArtifact.subarray(0, stored.length).equals(stored), true);
  assert.equal(runtimeArtifact.equals(decoded), true);
  assert.equal(runtimeArtifact.length, decoded.length);

  const manifest = JSON.parse(await readFile(result.manifestPath, "utf8")) as {
    sourceRomSha256: string;
    runtimeArtifacts: Array<{
      output: string;
      processor: string;
      overlayId: number;
      fileId: number;
      sourceRomSha256: string;
      representation: string;
      romOffset: number | null;
      storedRomOffset: number;
      storedSize: number;
      compressedSize: number;
      runtimeAddress: number;
      runtimeSize: number;
      bssSize: number;
      storedSha256: string;
      compressedPayloadSha256: string;
      runtimeSha256: string;
      outputSha256: string;
    }>;
  };

  assert.equal(manifest.sourceRomSha256, map.sha256);
  assert.equal(manifest.runtimeArtifacts.length, 1);
  const runtime = manifest.runtimeArtifacts[0]!;
  assert.equal(runtime.output, `runtime/overlays/arm9/overlay_${overlayId}.bin`);
  assert.equal(runtime.processor, "arm9");
  assert.equal(runtime.overlayId, overlayId);
  assert.equal(runtime.fileId, 0);
  assert.equal(runtime.sourceRomSha256, map.sha256);
  assert.equal(runtime.representation, "derived-blz");
  assert.equal(runtime.romOffset, null);
  assert.equal(runtime.storedRomOffset, COMPRESSED_ARM_CODE_STORED_OFFSET);
  assert.equal(runtime.storedSize, storedArtifact.length);
  assert.equal(runtime.compressedSize, stored.length);
  assert.equal(runtime.runtimeAddress, 0x02200000);
  assert.equal(runtime.runtimeSize, decoded.length);
  assert.equal(runtime.bssSize, 0x20);
  assert.match(runtime.storedSha256, /^[a-f0-9]{64}$/);
  assert.match(runtime.compressedPayloadSha256, /^[a-f0-9]{64}$/);
  assert.match(runtime.runtimeSha256, /^[a-f0-9]{64}$/);
  assert.equal(runtime.outputSha256, runtime.runtimeSha256);
});
