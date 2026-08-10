import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import test from "node:test";

import { crc16NdsHeader } from "../src/services/nds/header-rebuild.js";
import { hashFileSha256 } from "../src/services/nds/io.js";
import {
  createNdsOverlayRuntimeContext,
} from "../src/services/nds/overlay-runtime.js";
import { readNdsRomMap } from "../src/services/nds/rom-map.js";
import {
  loadNdsMutationManifest,
} from "../src/services/nds/mutation/manifest.js";
import {
  compileNdsMutationPlan,
  serializeResolvedNdsMutationPlan,
  type NdsResolvedMutationPlanV2,
} from "../src/services/nds/mutation/planner.js";
import { createMutationFixture } from "./helpers/nds-mutation-fixture.js";

function sha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function sha256Text(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

async function rebuildReadyFixture() {
  const fixture = await createMutationFixture();
  const bytes = await readFile(fixture.romPath);
  const crc = crc16NdsHeader(bytes.subarray(0, 0x15e));
  bytes.writeUInt16LE(crc, 0x15e);
  await writeFile(fixture.romPath, bytes);
  const map = await readNdsRomMap(fixture.romPath);
  const sourceSha256 = await hashFileSha256(fixture.romPath);
  return { fixture, map, sourceSha256 };
}

async function compileMixedPlan() {
  const ready = await rebuildReadyFixture();
  const sourceBytes = await readFile(ready.fixture.romPath);
  const ordinary = ready.map.filesystem.files.find(
    (file) => file.fileId === ready.fixture.ordinaryFileId,
  )!;
  const ordinarySource = sourceBytes.subarray(ordinary.startOffset, ordinary.endOffset);
  const ordinaryReplacement = await ready.fixture.writeArtifact(
    "artifacts/ordinary-v2.bin",
    Buffer.alloc(ordinary.size + 7, 0x66),
  );
  const added = await ready.fixture.writeArtifact(
    "artifacts/i2dt.bin",
    Buffer.from("RE-MCP-I2DT-V2", "ascii"),
  );

  const runtimeContext = createNdsOverlayRuntimeContext(ready.map);
  const overlaySource = await runtimeContext.getCompressedOverlay(
    "arm9",
    ready.fixture.compressedOverlayId,
  );
  const overlayRuntime = Buffer.from(overlaySource.bytes);
  overlayRuntime[0] = overlayRuntime[0]! ^ 0xff;
  const overlayReplacement = await ready.fixture.writeArtifact(
    "artifacts/overlay7-runtime.bin",
    overlayRuntime,
  );

  const manifestPath = await ready.fixture.writeManifest({
    formatVersion: 2,
    sourceSha256: ready.sourceSha256,
    operations: [
      {
        type: "replace-bytes",
        target: { component: "arm9", relativeOffset: 4 },
        expected: "a9a9",
        replacement: "0102",
      },
      {
        type: "replace-nitrofs-file",
        target: { fileId: ready.fixture.ordinaryFileId },
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
        target: {
          processor: "arm9",
          overlayId: ready.fixture.compressedOverlayId,
        },
        expectedStoredSha256: overlaySource.storedSha256,
        expectedRuntimeSha256: overlaySource.runtimeSha256,
        replacement: {
          artifact: overlayReplacement.relativePath,
          sha256: overlayReplacement.sha256,
        },
      },
    ],
  }, "plans/mixed-v2.json");

  const loaded = await loadNdsMutationManifest(ready.fixture.directory, manifestPath);
  const beforeSha256 = await hashFileSha256(ready.fixture.romPath);
  const plan = await compileNdsMutationPlan(
    ready.map,
    ready.fixture.directory,
    loaded,
  );
  const afterSha256 = await hashFileSha256(ready.fixture.romPath);
  assert.equal(beforeSha256, afterSha256);
  assert.equal(plan.formatVersion, 2);

  return {
    ...ready,
    plan: plan as NdsResolvedMutationPlanV2,
    loaded,
    ordinaryReplacement,
    added,
    overlayReplacement,
  };
}

test("v2 planner compiles the mixed rebuild into deterministic IDs, ranges, metadata, and header rewrites", async () => {
  const { fixture, map, plan } = await compileMixedPlan();

  assert.equal(plan.formatVersion, 2);
  assert.equal(plan.rebuildContractVersion, 1);
  assert.equal(plan.blzEncoderContractVersion, 1);
  assert.deepEqual(plan.operations.map((operation) => operation.kind), [
    "fixed",
    "relocated-file",
    "new-file",
    "decoded-overlay",
  ]);

  const relocated = plan.operations[1];
  const added = plan.operations[2];
  const overlay = plan.operations[3];
  assert.equal(relocated?.kind, "relocated-file");
  assert.equal(relocated.kind === "relocated-file" ? relocated.file.fileId : -1, fixture.ordinaryFileId);
  assert.equal(added?.kind, "new-file");
  assert.equal(added.kind === "new-file" ? added.file.fileId : -1, map.fat.length);
  assert.equal(overlay?.kind, "decoded-overlay");
  assert.equal(overlay.kind === "decoded-overlay" ? overlay.overlay.fileId : -1, fixture.compressedFileId);

  assert.deepEqual(
    plan.layout.segments.slice(0, 3).map((segment) => [segment.kind, segment.ownerId]),
    [
      ["relocated-file", `file:${fixture.ordinaryFileId}`],
      ["relocated-file", `overlay:arm9:${fixture.compressedOverlayId}`],
      ["new-file", `file:${map.fat.length}`],
    ],
  );
  for (const segment of plan.layout.segments.slice(0, 3)) {
    assert.equal(segment.start % 0x200, 0);
  }

  assert.equal(plan.finalFat.length, map.fat.length + 1);
  for (const segment of plan.layout.segments.slice(0, 3)) {
    const fileId = segment.ownerId.startsWith("overlay:")
      ? fixture.compressedFileId
      : Number(segment.ownerId.slice("file:".length));
    assert.equal(plan.finalFat[fileId]?.startOffset, segment.start);
    assert.equal(plan.finalFat[fileId]?.endOffset, segment.end);
  }
  assert.deepEqual(
    plan.layout.segments.slice(3).map((segment) => segment.kind),
    ["fnt", "fat", "arm9-overlay-table"],
  );
  assert.equal(plan.layout.segments.some((segment) => segment.kind === "arm7-overlay-table"), false);

  const sourceHeader = await readFile(fixture.romPath).then((bytes) => bytes.subarray(0, 0x160));
  const outputHeader = plan.headerPlan.outputHeaderBytes;
  assert.equal(outputHeader.readUInt8(0x14), plan.layout.deviceCapacity);
  assert.equal(outputHeader.readUInt32LE(0x80), plan.layout.logicalUsedSize);
  assert.deepEqual(outputHeader.subarray(0x58, 0x60), sourceHeader.subarray(0x58, 0x60));
  assert.ok(plan.headerPlan.rewrites.length > 0);
  assert.ok(plan.headerPlan.rewrites.every((rewrite) => [
    "device-capacity",
    "fnt",
    "fat",
    "arm9-overlay-table",
    "rom-used-size",
    "header-crc16",
  ].includes(rewrite.label)));
});

test("v2 build identity uses normalized artifact hashes in manifest order and excludes derived BLZ hash", async () => {
  const compiled = await compileMixedPlan();
  const canonicalIdentity = JSON.stringify({
    blzEncoderContractVersion: 1,
    format: "re-mcp-nds-build-identity",
    formatVersion: 2,
    manifestSha256: compiled.loaded.sha256,
    rebuildContractVersion: 1,
    replacementArtifactSha256: [
      compiled.ordinaryReplacement.sha256,
      compiled.added.sha256,
      compiled.overlayReplacement.sha256,
    ],
    sourceSha256: compiled.sourceSha256,
  });
  assert.equal(compiled.plan.buildId, sha256Text(canonicalIdentity));

  const overlay = compiled.plan.operations.find((operation) => operation.kind === "decoded-overlay");
  assert.ok(overlay && overlay.kind === "decoded-overlay");
  assert.notEqual(overlay.overlay.encodedSha256, compiled.overlayReplacement.sha256);
  assert.equal(canonicalIdentity.includes(overlay.overlay.encodedSha256), false);
});

test("v2 serialized plan and build ID are independent of absolute workspace path", async () => {
  const first = await compileMixedPlan();
  const second = await compileMixedPlan();

  assert.equal(first.sourceSha256, second.sourceSha256);
  assert.equal(first.loaded.sha256, second.loaded.sha256);
  assert.equal(first.plan.buildId, second.plan.buildId);
  assert.deepEqual(
    serializeResolvedNdsMutationPlan(first.plan),
    serializeResolvedNdsMutationPlan(second.plan),
  );
  const serialized = JSON.stringify(serializeResolvedNdsMutationPlan(first.plan));
  assert.equal(serialized.includes(first.fixture.directory), false);
  assert.equal(serialized.includes(second.fixture.directory), false);
});
