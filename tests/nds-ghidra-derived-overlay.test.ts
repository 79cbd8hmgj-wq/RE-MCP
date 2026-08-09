import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

import {
  generateNdsGhidraBridge,
  validateGeneratedGhidraBridge,
} from "../src/services/nds/ghidra-bridge.js";
import { readNdsRomMap } from "../src/services/nds/rom-map.js";
import {
  COMPRESSED_ARM_CODE_DECODED,
  COMPRESSED_ARM_CODE_OVERLAY_ID,
  COMPRESSED_ARM_CODE_STORED,
  createCompressedArmCodeFixture,
} from "./helpers/nds-compressed-code-fixture.js";
import {
  createNdsFixture,
  writeFatEntry,
  writeOverlayRecord,
} from "./helpers/nds-fixture.js";

function sha256(bytes: Buffer): string {
  return createHash("sha256").update(bytes).digest("hex");
}

test("Ghidra bridge v2 imports a compressed overlay from the validated derived runtime artifact", async () => {
  const { fixture, map } = await createCompressedArmCodeFixture();
  const bridge = await generateNdsGhidraBridge(map, fixture.directory);

  assert.equal(bridge.manifest.formatVersion, 2);
  const arm9 = bridge.manifest.processors.find((entry) => entry.processor === "arm9");
  assert.ok(arm9);
  const overlay = arm9.overlays.find((entry) => entry.overlayId === COMPRESSED_ARM_CODE_OVERLAY_ID);
  assert.ok(overlay);

  assert.equal(overlay.importStatus, "importable-derived");
  assert.equal(overlay.representation, "derived-blz");
  assert.equal(
    overlay.artifactPath,
    `../runtime/overlays/arm9/overlay_${COMPRESSED_ARM_CODE_OVERLAY_ID}.bin`,
  );
  assert.equal(overlay.initializedSize, COMPRESSED_ARM_CODE_DECODED.length);
  assert.equal(overlay.ramSize, COMPRESSED_ARM_CODE_DECODED.length);
  assert.equal(overlay.bssSize, 0x20);
  assert.equal(overlay.compressed, true);
  assert.equal(overlay.compressedSize, COMPRESSED_ARM_CODE_STORED.length);

  const storedPath = path.join(
    fixture.directory,
    "analysis",
    "generated",
    "nds",
    map.sha256Prefix,
    "overlays",
    "arm9",
    `overlay_${COMPRESSED_ARM_CODE_OVERLAY_ID}.bin`,
  );
  const runtimePath = path.join(
    fixture.directory,
    "analysis",
    "generated",
    "nds",
    map.sha256Prefix,
    "runtime",
    "overlays",
    "arm9",
    `overlay_${COMPRESSED_ARM_CODE_OVERLAY_ID}.bin`,
  );
  const stored = await readFile(storedPath);
  const runtime = await readFile(runtimePath);

  assert.equal(overlay.storedSize, stored.length);
  assert.equal(overlay.storedSha256, sha256(stored));
  assert.equal(overlay.runtimeSha256, sha256(runtime));
  assert.equal(runtime.equals(COMPRESSED_ARM_CODE_DECODED), true);
  assert.notEqual(overlay.storedSha256, overlay.runtimeSha256);
  assert.equal(
    bridge.manifest.artifacts.some((artifact) => artifact.path === overlay.artifactPath),
    true,
  );
  assert.equal(
    JSON.stringify(bridge.manifest).includes("not-imported-compressed"),
    false,
  );

  await validateGeneratedGhidraBridge(bridge);
});

test("Ghidra bridge v2 hashes only the initialized prefix imported from oversized uncompressed backing", async () => {
  const fixture = await createNdsFixture({
    fileSize: 0x5000,
    arm9Size: 0x20,
    arm7Size: 0x20,
    fatOffset: 0x900,
    fatSize: 8,
    arm9OverlayOffset: 0xa00,
    arm9OverlaySize: 32,
  });

  writeFatEntry(fixture.buffer, 0x900, 0, 0x1000, 0x1040);
  writeOverlayRecord(fixture.buffer, 0xa00, 0, {
    overlayId: 5,
    ramAddress: 0x02200000,
    ramSize: 0x20,
    bssSize: 0x10,
    staticInitStart: 0,
    staticInitEnd: 0,
    fileId: 0,
    compressedSize: 0,
    flags: 0,
  });

  fixture.buffer.fill(0x11, 0x1000, 0x1020);
  fixture.buffer.fill(0xee, 0x1020, 0x1040);
  fixture.buffer.set([0x1e, 0xff, 0x2f, 0xe1], 0x200);
  fixture.buffer.set([0x1e, 0xff, 0x2f, 0xe1], 0x600);
  fixture.buffer.set([0x1e, 0xff, 0x2f, 0xe1], 0x1000);
  await fixture.write();

  const map = await readNdsRomMap(fixture.romPath);
  const bridge = await generateNdsGhidraBridge(map, fixture.directory);
  const arm9 = bridge.manifest.processors.find((entry) => entry.processor === "arm9");
  assert.ok(arm9);
  const overlay = arm9.overlays.find((entry) => entry.overlayId === 5);
  assert.ok(overlay);

  const storedPath = path.join(
    fixture.directory,
    "analysis",
    "generated",
    "nds",
    map.sha256Prefix,
    "overlays",
    "arm9",
    "overlay_5.bin",
  );
  const stored = await readFile(storedPath);

  assert.equal(overlay.importStatus, "importable");
  assert.equal(overlay.representation, "rom-file-backed");
  assert.equal(overlay.initializedSize, 0x20);
  assert.equal(overlay.storedSize, 0x40);
  assert.equal(overlay.storedSha256, sha256(stored));
  assert.equal(overlay.runtimeSha256, sha256(stored.subarray(0, 0x20)));
  assert.notEqual(overlay.runtimeSha256, overlay.storedSha256);

  await validateGeneratedGhidraBridge(bridge);
});
