import assert from "node:assert/strict";
import { access, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

import {
  generateNdsGhidraBridge,
  validateGeneratedGhidraBridge,
} from "../src/services/nds/ghidra-bridge.js";
import { NdsError } from "../src/services/nds/errors.js";
import { hashFileSha256 } from "../src/services/nds/io.js";
import { readNdsRomMap } from "../src/services/nds/rom-map.js";
import {
  COMPRESSED_ARM_CODE_DECODED,
  COMPRESSED_ARM_CODE_STORED,
} from "./helpers/nds-compressed-code-fixture.js";
import {
  createNdsFixture,
  writeFatEntry,
  writeOverlayRecord,
} from "./helpers/nds-fixture.js";

const ARM_BX_LR = Buffer.from([0x1e, 0xff, 0x2f, 0xe1]);

async function createBridgeFixture() {
  const compressedBackingSize = COMPRESSED_ARM_CODE_STORED.length + 8;
  const fixture = await createNdsFixture({
    fileSize: 0x6000,
    arm9Size: 0x20,
    arm7Size: 0x20,
    fatOffset: 0x900,
    fatSize: 16,
    arm9OverlayOffset: 0xa00,
    arm9OverlaySize: 64,
  });

  writeFatEntry(fixture.buffer, 0x900, 0, 0x1000, 0x1020);
  writeFatEntry(fixture.buffer, 0x900, 1, 0x1100, 0x1100 + compressedBackingSize);
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
  writeOverlayRecord(fixture.buffer, 0xa00, 1, {
    overlayId: 9,
    ramAddress: 0x02210000,
    ramSize: COMPRESSED_ARM_CODE_DECODED.length,
    bssSize: 0x20,
    staticInitStart: 0,
    staticInitEnd: 0,
    fileId: 1,
    compressedSize: COMPRESSED_ARM_CODE_STORED.length,
    flags: 1,
  });

  ARM_BX_LR.copy(fixture.buffer, 0x200);
  ARM_BX_LR.copy(fixture.buffer, 0x600);
  ARM_BX_LR.copy(fixture.buffer, 0x1000);
  COMPRESSED_ARM_CODE_STORED.copy(fixture.buffer, 0x1100);
  fixture.buffer.fill(
    0x5a,
    0x1100 + COMPRESSED_ARM_CODE_STORED.length,
    0x1100 + compressedBackingSize,
  );
  await fixture.write();

  return {
    fixture,
    map: await readNdsRomMap(fixture.romPath),
  };
}

function artifactAbsolute(bridgeRoot: string, relative: string): string {
  return path.resolve(bridgeRoot, relative);
}

test("Ghidra bridge generation is deterministic, bounded, and imports validated derived overlays", async () => {
  const { fixture, map } = await createBridgeFixture();
  const bridge = await generateNdsGhidraBridge(map, fixture.directory);

  assert.equal(
    bridge.bridgeRoot,
    path.join(fixture.directory, "analysis", "generated", "nds", map.sha256Prefix, "ghidra-bridge"),
  );
  assert.equal(bridge.manifest.formatVersion, 2);
  assert.equal(bridge.manifest.sourceRomSha256, map.sha256);
  assert.equal(bridge.manifestSha256, await hashFileSha256(bridge.manifestPath));
  assert.deepEqual(bridge.manifest.discovery.map((entry) => entry.processor), ["arm9", "arm7"]);
  assert.deepEqual(
    bridge.manifest.discovery.map((entry) => entry.functions.map((fn) => fn.id)),
    [["arm9:main:02000000:arm"], ["arm7:main:03800000:arm"]],
  );

  const arm9 = bridge.manifest.processors.find((entry) => entry.processor === "arm9")!;
  assert.deepEqual(arm9.overlays.map((entry) => [entry.overlayId, entry.importStatus]), [
    [5, "importable"],
    [9, "importable-derived"],
  ]);
  const derived = arm9.overlays.find((entry) => entry.overlayId === 9)!;
  assert.equal(derived.representation, "derived-blz");
  assert.equal(derived.initializedSize, COMPRESSED_ARM_CODE_DECODED.length);
  assert.equal(derived.artifactPath, "../runtime/overlays/arm9/overlay_9.bin");

  for (const relative of [
    "manifest.json",
    "evidence/functions.json",
    "evidence/calls.json",
    "scripts/ReMcpPrepareProgram.java",
    "scripts/ReMcpImportEvidence.java",
    "scripts/ReMcpRecordAnalysis.java",
  ]) {
    await access(path.join(bridge.bridgeRoot, relative));
  }
  await access(path.join(bridge.bridgeRoot, "results"));

  for (const artifact of bridge.manifest.artifacts) {
    const absolute = artifactAbsolute(bridge.bridgeRoot, artifact.path);
    assert.equal(await hashFileSha256(absolute), artifact.sha256, artifact.path);
    assert.equal((await readFile(absolute)).length, artifact.size, artifact.path);
  }

  const functions = JSON.parse(
    await readFile(path.join(bridge.bridgeRoot, "evidence", "functions.json"), "utf8"),
  ) as { processors: Array<{ processor: string; functions: unknown[] }> };
  assert.deepEqual(functions.processors.map((entry) => [entry.processor, entry.functions.length]), [
    ["arm9", 1],
    ["arm7", 1],
  ]);

  await validateGeneratedGhidraBridge(bridge);
});

test("Ghidra bridge validation rejects tampered evidence", async () => {
  const { fixture, map } = await createBridgeFixture();
  const bridge = await generateNdsGhidraBridge(map, fixture.directory);
  const functionsPath = path.join(bridge.bridgeRoot, "evidence", "functions.json");
  await writeFile(functionsPath, "{}\n", "utf8");

  await assert.rejects(
    validateGeneratedGhidraBridge(bridge),
    (error: unknown) => error instanceof NdsError && error.category === "bridge-generation-failed",
  );
});

test("Ghidra bridge validation rejects a tampered derived overlay artifact", async () => {
  const { fixture, map } = await createBridgeFixture();
  const bridge = await generateNdsGhidraBridge(map, fixture.directory);
  const derived = bridge.manifest.processors
    .find((entry) => entry.processor === "arm9")!
    .overlays.find((entry) => entry.overlayId === 9)!;
  const derivedPath = artifactAbsolute(bridge.bridgeRoot, derived.artifactPath);
  const original = await readFile(derivedPath);
  await writeFile(derivedPath, Buffer.concat([Buffer.from([original[0]! ^ 0xff]), original.subarray(1)]));

  await assert.rejects(
    validateGeneratedGhidraBridge(bridge),
    (error: unknown) => error instanceof NdsError && error.category === "bridge-generation-failed",
  );
});

test("Ghidra bridge generation rejects a stale ROM identity without promoting a bridge", async () => {
  const { fixture, map } = await createBridgeFixture();
  fixture.buffer[0x200] = 0;
  await fixture.write();

  await assert.rejects(
    generateNdsGhidraBridge(map, fixture.directory),
    (error: unknown) => error instanceof NdsError && error.category === "invalid-rom",
  );

  const bridgeRoot = path.join(
    fixture.directory,
    "analysis",
    "generated",
    "nds",
    map.sha256Prefix,
    "ghidra-bridge",
  );
  await assert.rejects(access(bridgeRoot));
  await rm(path.join(fixture.directory, "analysis"), { recursive: true, force: true });
});
