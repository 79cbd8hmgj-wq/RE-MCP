import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

import { crc16NdsHeader } from "../src/services/nds/header-rebuild.js";
import { hashFileSha256 } from "../src/services/nds/io.js";
import { createNdsOverlayRuntimeContext } from "../src/services/nds/overlay-runtime.js";
import { readNdsRomMap } from "../src/services/nds/rom-map.js";
import { buildNdsMutation, verifyPublishedNdsMutationBuild } from "../src/services/nds/mutation/build.js";
import { loadNdsMutationManifest } from "../src/services/nds/mutation/manifest.js";
import { createMutationFixture } from "./helpers/nds-mutation-fixture.js";

function sha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

async function buildV2Fixture() {
  const fixture = await createMutationFixture();
  const sourceBytes = await readFile(fixture.romPath);
  sourceBytes.writeUInt16LE(crc16NdsHeader(sourceBytes.subarray(0, 0x15e)), 0x15e);
  await writeFile(fixture.romPath, sourceBytes);
  const map = await readNdsRomMap(fixture.romPath);
  const sourceSha256 = await hashFileSha256(fixture.romPath);

  const ordinary = map.filesystem.files.find((file) => file.fileId === fixture.ordinaryFileId)!;
  const ordinarySource = sourceBytes.subarray(ordinary.startOffset, ordinary.endOffset);
  const ordinaryReplacementBytes = Buffer.alloc(ordinary.size + 7, 0x66);
  const ordinaryReplacement = await fixture.writeArtifact(
    "artifacts/ordinary-v2-build.bin",
    ordinaryReplacementBytes,
  );
  const addedBytes = Buffer.from("RE-MCP-I2DT-V2-BUILD", "ascii");
  const added = await fixture.writeArtifact("artifacts/i2dt-build.bin", addedBytes);

  const sourceRuntimeContext = createNdsOverlayRuntimeContext(map);
  const sourceOverlay = await sourceRuntimeContext.getCompressedOverlay(
    "arm9",
    fixture.compressedOverlayId,
  );
  const replacementRuntimeBytes = Buffer.from(sourceOverlay.bytes);
  replacementRuntimeBytes[0] = replacementRuntimeBytes[0]! ^ 0xff;
  const overlayReplacement = await fixture.writeArtifact(
    "artifacts/overlay7-runtime-build.bin",
    replacementRuntimeBytes,
  );

  const manifestPath = await fixture.writeManifest({
    formatVersion: 2,
    sourceSha256,
    outputFilename: "rebuilt-v2.nds",
    operations: [
      {
        type: "replace-bytes",
        target: { component: "arm9", relativeOffset: 4 },
        expected: "a9a9",
        replacement: "0102",
      },
      {
        type: "replace-nitrofs-file",
        target: { fileId: fixture.ordinaryFileId },
        expectedOriginalSha256: sha256(ordinarySource),
        replacement: {
          artifact: ordinaryReplacement.relativePath,
          sha256: ordinaryReplacement.sha256,
        },
      },
      {
        type: "add-nitrofs-file",
        path: "re_mcp/attributes/i2dt.bin",
        replacement: {
          artifact: added.relativePath,
          sha256: added.sha256,
        },
      },
      {
        type: "replace-decoded-overlay",
        target: { processor: "arm9", overlayId: fixture.compressedOverlayId },
        expectedStoredSha256: sourceOverlay.storedSha256,
        expectedRuntimeSha256: sourceOverlay.runtimeSha256,
        replacement: {
          artifact: overlayReplacement.relativePath,
          sha256: overlayReplacement.sha256,
        },
      },
    ],
  }, "plans/build-v2.json");
  const loaded = await loadNdsMutationManifest(fixture.directory, manifestPath);
  const sourceBeforeBuild = await hashFileSha256(fixture.romPath);
  const result = await buildNdsMutation(map, fixture.directory, loaded);

  return {
    fixture,
    map,
    loaded,
    result,
    sourceBeforeBuild,
    ordinaryReplacementBytes,
    addedBytes,
    replacementRuntimeBytes,
  };
}

test("materializes and semantically verifies a mixed v2 NDS rebuild", async () => {
  const built = await buildV2Fixture();
  const outputBytes = await readFile(built.result.outputRomPath);
  const outputMap = await readNdsRomMap(built.result.outputRomPath);

  assert.equal(await hashFileSha256(built.fixture.romPath), built.sourceBeforeBuild);
  assert.ok(built.result.verification.outputSize > built.map.fileSize);
  assert.equal(built.result.verification.unexpectedChangedBytes, 0);
  assert.equal(built.result.verification.rebuildSemanticsVerified, true);
  assert.equal(outputBytes.length, built.result.verification.outputSize);

  const ordinary = outputMap.filesystem.files.find(
    (file) => file.fileId === built.fixture.ordinaryFileId,
  )!;
  assert.equal(
    sha256(outputBytes.subarray(ordinary.startOffset, ordinary.endOffset)),
    sha256(built.ordinaryReplacementBytes),
  );

  const added = outputMap.filesystem.files.find(
    (file) => file.path === "re_mcp/attributes/i2dt.bin",
  )!;
  assert.ok(added);
  assert.equal(
    sha256(outputBytes.subarray(added.startOffset, added.endOffset)),
    sha256(built.addedBytes),
  );

  const outputRuntime = await createNdsOverlayRuntimeContext(outputMap).getCompressedOverlay(
    "arm9",
    built.fixture.compressedOverlayId,
  );
  assert.equal(outputRuntime.runtimeSha256, sha256(built.replacementRuntimeBytes));

  const verificationEvidence = JSON.parse(
    await readFile(path.join(built.result.outputRoot, "verification.json"), "utf8"),
  ) as {
    rebuildSemanticsVerified: boolean;
    rebuildContractVersion: number;
    blzEncoderContractVersion: number;
    operationCount: number;
    unexpectedChangedBytes: number;
  };
  assert.equal(verificationEvidence.rebuildSemanticsVerified, true);
  assert.equal(verificationEvidence.rebuildContractVersion, 1);
  assert.equal(verificationEvidence.blzEncoderContractVersion, 1);
  assert.equal(verificationEvidence.operationCount, 4);
  assert.equal(verificationEvidence.unexpectedChangedBytes, 0);
});

test("reuses a v2 deterministic build only after fresh semantic verification", async () => {
  const built = await buildV2Fixture();
  const reused = await buildNdsMutation(built.map, built.fixture.directory, built.loaded);
  assert.equal(reused.reused, true);
  assert.equal(reused.outputSha256, built.result.outputSha256);
  assert.equal(reused.verification.rebuildSemanticsVerified, true);

  const verified = await verifyPublishedNdsMutationBuild(
    built.map,
    built.fixture.directory,
    built.loaded,
  );
  assert.equal(verified.reused, true);
  assert.equal(verified.outputSha256, built.result.outputSha256);
  assert.equal(verified.verification.rebuildSemanticsVerified, true);
});
