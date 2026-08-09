import assert from "node:assert/strict";
import { mkdir, readFile, rename, rm } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

import { NdsError } from "../src/services/nds/errors.js";
import {
  extractNdsAnalysisBundle,
  extractNdsComponent,
  type NdsExtractionFs,
} from "../src/services/nds/extraction.js";
import { hashFileSha256 } from "../src/services/nds/io.js";
import { readNdsRomMap } from "../src/services/nds/rom-map.js";
import {
  COMPRESSED_ARM_CODE_DECODED,
  COMPRESSED_ARM_CODE_STORED,
} from "./helpers/nds-compressed-code-fixture.js";
import {
  createNdsFixture,
  encodeFntFileEntry,
  writeFatEntry,
  writeFntMainRecord,
  writeFntSubtable,
  writeOverlayRecord,
} from "./helpers/nds-fixture.js";

const COMPRESSED_BACKING_SIZE = 0x80;

function expectedCompressedBacking(): Buffer {
  return Buffer.concat([
    COMPRESSED_ARM_CODE_STORED,
    Buffer.alloc(COMPRESSED_BACKING_SIZE - COMPRESSED_ARM_CODE_STORED.length, 0xdd),
  ]);
}

async function buildExtractionMap() {
  const fixture = await createNdsFixture({
    fileSize: 0x5000,
    fntSize: 0x40,
    fatSize: 16,
    arm9OverlaySize: 32,
  });
  writeFatEntry(fixture.buffer, 0x900, 0, 0x1200, 0x1220);
  writeFatEntry(fixture.buffer, 0x900, 1, 0x1300, 0x1380);
  writeFntMainRecord(fixture.buffer, 0x800, 0, 8, 0, 1);
  writeFntSubtable(fixture.buffer, 0x800, 8, [encodeFntFileEntry("asset.bin")]);
  writeOverlayRecord(fixture.buffer, 0xa00, 0, {
    overlayId: 7,
    ramAddress: 0x02200000,
    ramSize: COMPRESSED_ARM_CODE_DECODED.length,
    bssSize: 0x20,
    staticInitStart: 0,
    staticInitEnd: 0,
    fileId: 1,
    compressedSize: COMPRESSED_ARM_CODE_STORED.length,
    flags: 1,
  });
  fixture.buffer.fill(0xa9, 0x200, 0x400);
  fixture.buffer.fill(0xa7, 0x600, 0x700);
  fixture.buffer.fill(0xcc, 0x1200, 0x1220);
  expectedCompressedBacking().copy(fixture.buffer, 0x1300);
  await fixture.write();
  return { fixture, map: await readNdsRomMap(fixture.romPath) };
}

test("extracts ARM9 to the deterministic ROM-specific generated path", async () => {
  const { fixture, map } = await buildExtractionMap();
  const sourceBefore = await hashFileSha256(fixture.romPath);
  const artifact = await extractNdsComponent(map, fixture.directory, { component: "arm9" });

  assert.equal(
    artifact.output,
    path.join(fixture.directory, "analysis", "generated", "nds", map.sha256Prefix, "arm9.bin"),
  );
  assert.equal(artifact.sourceRomSha256, map.sha256);
  assert.equal(artifact.romOffset, 0x200);
  assert.equal(artifact.size, 0x200);
  assert.equal(artifact.ramAddress, 0x02000000);
  assert.equal(artifact.processor, "arm9");
  assert.equal((await readFile(artifact.output)).equals(Buffer.alloc(0x200, 0xa9)), true);
  assert.equal(artifact.outputSha256, await hashFileSha256(artifact.output));
  assert.equal(await hashFileSha256(fixture.romPath), sourceBefore);
});

test("extracts compressed overlays as exact stored FAT-backed bytes", async () => {
  const { fixture, map } = await buildExtractionMap();
  const artifact = await extractNdsComponent(map, fixture.directory, {
    component: "arm9-overlay",
    overlayId: 7,
  });
  assert.equal(artifact.compressed, true);
  assert.equal(artifact.compressedSize, COMPRESSED_ARM_CODE_STORED.length);
  assert.equal(artifact.size, COMPRESSED_BACKING_SIZE);
  assert.equal(artifact.ramAddress, 0x02200000);
  assert.equal((await readFile(artifact.output)).equals(expectedCompressedBacking()), true);
});

test("extracts NitroFS files by canonical file ID and parsed path", async () => {
  const { fixture, map } = await buildExtractionMap();
  const byId = await extractNdsComponent(map, fixture.directory, {
    component: "nitrofs-file",
    fileId: 0,
  });
  const byPath = await extractNdsComponent(map, fixture.directory, {
    component: "nitrofs-path",
    filePath: "asset.bin",
  });
  assert.equal(byId.output, byPath.output);
  assert.equal(byId.fileId, 0);
  assert.equal((await readFile(byId.output)).equals(Buffer.alloc(0x20, 0xcc)), true);
});

test("rejects unknown overlay and NitroFS selectors", async () => {
  const { fixture, map } = await buildExtractionMap();
  await assert.rejects(
    extractNdsComponent(map, fixture.directory, { component: "arm9-overlay", overlayId: 999 }),
    (error: unknown) => error instanceof NdsError && error.category === "unknown-overlay-id",
  );
  await assert.rejects(
    extractNdsComponent(map, fixture.directory, { component: "nitrofs-file", fileId: 999 }),
    (error: unknown) => error instanceof NdsError && error.category === "unknown-file-id",
  );
  await assert.rejects(
    extractNdsComponent(map, fixture.directory, { component: "nitrofs-path", filePath: "../asset.bin" }),
    (error: unknown) => error instanceof NdsError && error.category === "unknown-file-id",
  );
});

test("refuses extraction if the source ROM no longer matches the canonical map identity", async () => {
  const { fixture, map } = await buildExtractionMap();
  fixture.buffer[0x1400] = 0x5a;
  await fixture.write();
  await assert.rejects(
    extractNdsComponent(map, fixture.directory, { component: "arm9" }),
    (error: unknown) => error instanceof NdsError && error.category === "invalid-rom",
  );
});

test("builds a complete deterministic analysis bundle without dumping every NitroFS file", async () => {
  const { fixture, map } = await buildExtractionMap();
  const result = await extractNdsAnalysisBundle(map, fixture.directory);
  const expectedRoot = path.join(
    fixture.directory,
    "analysis",
    "generated",
    "nds",
    map.sha256Prefix,
  );
  assert.equal(result.outputRoot, expectedRoot);
  assert.equal(result.manifestPath, path.join(expectedRoot, "manifest.json"));

  const manifest = JSON.parse(await readFile(result.manifestPath, "utf8")) as {
    sourceRomSha256: string;
    artifacts: Array<{ output: string; outputSha256: string; compressed: boolean }>;
    runtimeArtifacts: Array<{ output: string; representation: string }>;
  };
  assert.equal(manifest.sourceRomSha256, map.sha256);
  assert.equal(manifest.artifacts.some((artifact) => artifact.output === "arm9.bin"), true);
  assert.equal(manifest.artifacts.some((artifact) => artifact.output === "arm7.bin"), true);
  assert.equal(
    manifest.artifacts.some((artifact) => artifact.output === "overlays/arm9/overlay_7.bin" && artifact.compressed),
    true,
  );
  assert.equal(
    manifest.runtimeArtifacts.some(
      (artifact) => artifact.output === "runtime/overlays/arm9/overlay_7.bin"
        && artifact.representation === "derived-blz",
    ),
    true,
  );
  assert.equal(
    (await readFile(path.join(expectedRoot, "runtime", "overlays", "arm9", "overlay_7.bin")))
      .equals(COMPRESSED_ARM_CODE_DECODED),
    true,
  );
  await readFile(path.join(expectedRoot, "address-map.json"));
  await readFile(path.join(expectedRoot, "filesystem.json"));
  await readFile(path.join(expectedRoot, "overlays.json"));
  await assert.rejects(readFile(path.join(expectedRoot, "nitrofs", "file_0.bin")));
});

test("failed bundle promotion never leaves a completed-looking final bundle", async () => {
  const { fixture, map } = await buildExtractionMap();
  const finalRoot = path.join(
    fixture.directory,
    "analysis",
    "generated",
    "nds",
    map.sha256Prefix,
  );
  let blockedPromotion = false;
  const failingFs: NdsExtractionFs = {
    mkdir,
    rm,
    async rename(source, destination) {
      if (
        !blockedPromotion
        && source.includes(`${map.sha256Prefix}.tmp-`)
        && destination === finalRoot
      ) {
        blockedPromotion = true;
        throw new Error("forced bundle promotion failure");
      }
      await rename(source, destination);
    },
  };

  await assert.rejects(
    extractNdsAnalysisBundle(map, fixture.directory, failingFs),
    (error: unknown) => error instanceof NdsError && error.category === "generated-path-failure",
  );
  assert.equal(blockedPromotion, true);
  await assert.rejects(readFile(path.join(finalRoot, "manifest.json")));
});
