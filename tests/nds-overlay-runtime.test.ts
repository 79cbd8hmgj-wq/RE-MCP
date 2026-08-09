import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { NdsError } from "../src/services/nds/errors.js";
import {
  createNdsOverlayRuntimeContext,
  type NdsOverlayRuntimeLimits,
} from "../src/services/nds/overlay-runtime.js";
import { readNdsRomMap } from "../src/services/nds/rom-map.js";
import {
  createNdsFixture,
  writeFatEntry,
  writeOverlayRecord,
} from "./helpers/nds-fixture.js";

const BLZ_FIXTURE_ROOT = fileURLToPath(new URL("./fixtures/nds-blz/", import.meta.url));
const ARM9_OVERLAY_ID = 7;
const ARM7_OVERLAY_ID = 11;
const ARM9_FILE_ID = 0;
const ARM7_FILE_ID = 1;
const ARM9_ROM_OFFSET = 0x1400;
const ARM7_ROM_OFFSET = 0x1600;

function sha256(bytes: Buffer): string {
  return createHash("sha256").update(bytes).digest("hex");
}

async function blzPair(name = "backreference"): Promise<{
  readonly compressed: Buffer;
  readonly decoded: Buffer;
}> {
  const [compressed, decoded] = await Promise.all([
    readFile(path.join(BLZ_FIXTURE_ROOT, `${name}.bin`)),
    readFile(path.join(BLZ_FIXTURE_ROOT, `${name}.dec.bin`)),
  ]);
  return { compressed, decoded };
}

async function createCompressedRuntimeFixture(options: {
  readonly arm9TrailingByte?: number;
  readonly arm7TrailingByte?: number;
  readonly arm9CompressedSizeOverride?: number;
  readonly arm9Flags?: number;
} = {}) {
  const pair = await blzPair();
  const trailingSize = 8;
  const arm9Backing = Buffer.concat([
    pair.compressed,
    Buffer.alloc(trailingSize, options.arm9TrailingByte ?? 0xa5),
  ]);
  const arm7Backing = Buffer.concat([
    pair.compressed,
    Buffer.alloc(trailingSize, options.arm7TrailingByte ?? 0x5a),
  ]);
  const fixture = await createNdsFixture({
    fileSize: 0x4000,
    fatSize: 16,
    arm9OverlaySize: 32,
    arm7OverlaySize: 32,
  });

  writeFatEntry(
    fixture.buffer,
    0x900,
    ARM9_FILE_ID,
    ARM9_ROM_OFFSET,
    ARM9_ROM_OFFSET + arm9Backing.length,
  );
  writeFatEntry(
    fixture.buffer,
    0x900,
    ARM7_FILE_ID,
    ARM7_ROM_OFFSET,
    ARM7_ROM_OFFSET + arm7Backing.length,
  );
  writeOverlayRecord(fixture.buffer, 0xa00, 0, {
    overlayId: ARM9_OVERLAY_ID,
    ramAddress: 0x02200000,
    ramSize: pair.decoded.length,
    bssSize: 0x20,
    staticInitStart: 0,
    staticInitEnd: 0,
    fileId: ARM9_FILE_ID,
    compressedSize: options.arm9CompressedSizeOverride ?? pair.compressed.length,
    flags: options.arm9Flags ?? 1,
  });
  writeOverlayRecord(fixture.buffer, 0xb00, 0, {
    overlayId: ARM7_OVERLAY_ID,
    ramAddress: 0x03801000,
    ramSize: pair.decoded.length,
    bssSize: 0x10,
    staticInitStart: 0,
    staticInitEnd: 0,
    fileId: ARM7_FILE_ID,
    compressedSize: pair.compressed.length,
    flags: 1,
  });
  arm9Backing.copy(fixture.buffer, ARM9_ROM_OFFSET);
  arm7Backing.copy(fixture.buffer, ARM7_ROM_OFFSET);
  await fixture.write();

  return {
    fixture,
    pair,
    arm9Backing,
    arm7Backing,
    map: await readNdsRomMap(fixture.romPath),
  };
}

async function expectCategory(
  operation: () => Promise<unknown>,
  category: string,
): Promise<void> {
  await assert.rejects(operation(), (error: unknown) => {
    assert.ok(error instanceof NdsError);
    assert.equal(error.category, category);
    return true;
  });
}

test("compressed ARM9 overlay runtime image keeps full-storage, payload, and decoded provenance separate", async () => {
  const { map, pair, arm9Backing } = await createCompressedRuntimeFixture();
  const overlay = map.overlays.arm9[0]!;
  const context = createNdsOverlayRuntimeContext(map);

  const image = await context.getCompressedOverlay("arm9", ARM9_OVERLAY_ID);

  assert.equal(image.processor, "arm9");
  assert.equal(image.overlayId, ARM9_OVERLAY_ID);
  assert.equal(image.fileId, ARM9_FILE_ID);
  assert.equal(image.sourceRomSha256, map.sha256);
  assert.equal(image.storedRomOffset, ARM9_ROM_OFFSET);
  assert.equal(image.storedSize, arm9Backing.length);
  assert.equal(image.compressedSize, pair.compressed.length);
  assert.equal(image.storedSha256, sha256(arm9Backing));
  assert.equal(image.compressedPayloadSha256, sha256(pair.compressed));
  assert.equal(image.runtimeAddress, overlay.ramAddress);
  assert.equal(image.runtimeSize, pair.decoded.length);
  assert.equal(image.bssSize, 0x20);
  assert.equal(image.representation, "derived-blz");
  assert.equal(image.runtimeSha256, sha256(pair.decoded));
  assert.deepEqual(image.bytes, pair.decoded);
  assert.equal(image.bytes.length, overlay.ramSize);
  assert.equal(image.bytes.length, pair.decoded.length);
});

test("compressed ARM7 overlay uses the same canonical runtime-image service", async () => {
  const { map, pair, arm7Backing } = await createCompressedRuntimeFixture();
  const image = await createNdsOverlayRuntimeContext(map)
    .getCompressedOverlay("arm7", ARM7_OVERLAY_ID);

  assert.equal(image.processor, "arm7");
  assert.equal(image.overlayId, ARM7_OVERLAY_ID);
  assert.equal(image.storedSize, arm7Backing.length);
  assert.equal(image.storedSha256, sha256(arm7Backing));
  assert.equal(image.compressedPayloadSha256, sha256(pair.compressed));
  assert.deepEqual(image.bytes, pair.decoded);
  assert.equal(image.bssSize, 0x10);
});

test("trailing FAT backing bytes affect only full-storage provenance", async () => {
  const left = await createCompressedRuntimeFixture({ arm9TrailingByte: 0x11 });
  const right = await createCompressedRuntimeFixture({ arm9TrailingByte: 0xee });

  const leftImage = await createNdsOverlayRuntimeContext(left.map)
    .getCompressedOverlay("arm9", ARM9_OVERLAY_ID);
  const rightImage = await createNdsOverlayRuntimeContext(right.map)
    .getCompressedOverlay("arm9", ARM9_OVERLAY_ID);

  assert.notEqual(leftImage.storedSha256, rightImage.storedSha256);
  assert.equal(leftImage.compressedPayloadSha256, rightImage.compressedPayloadSha256);
  assert.equal(leftImage.runtimeSha256, rightImage.runtimeSha256);
  assert.deepEqual(leftImage.bytes, rightImage.bytes);
});

test("compressed runtime service rejects invalid canonical compressedSize geometry", async () => {
  const tooSmall = await createCompressedRuntimeFixture({ arm9CompressedSizeOverride: 7 });
  await expectCategory(
    () => createNdsOverlayRuntimeContext(tooSmall.map)
      .getCompressedOverlay("arm9", ARM9_OVERLAY_ID),
    "compressed-overlay-runtime-unavailable",
  );

  const tooLarge = await createCompressedRuntimeFixture({ arm9CompressedSizeOverride: 0x100 });
  assert.ok(tooLarge.map.overlays.arm9[0]!.compressedSize > tooLarge.map.overlays.arm9[0]!.romSize);
  await expectCategory(
    () => createNdsOverlayRuntimeContext(tooLarge.map)
      .getCompressedOverlay("arm9", ARM9_OVERLAY_ID),
    "compressed-overlay-runtime-unavailable",
  );
});

test("compressed runtime service rejects unknown and uncompressed overlays", async () => {
  const { fixture } = await createCompressedRuntimeFixture({ arm9Flags: 0 });
  const map = await readNdsRomMap(fixture.romPath);
  const context = createNdsOverlayRuntimeContext(map);

  await expectCategory(
    () => context.getCompressedOverlay("arm9", 999),
    "compressed-overlay-runtime-unavailable",
  );
  await expectCategory(
    () => context.getCompressedOverlay("arm9", ARM9_OVERLAY_ID),
    "compressed-overlay-runtime-unavailable",
  );
});

test("compressed runtime context caches one overlay and charges decoded bytes once", async () => {
  const { map, pair } = await createCompressedRuntimeFixture();
  const context = createNdsOverlayRuntimeContext(map);

  const first = await context.getCompressedOverlay("arm9", ARM9_OVERLAY_ID);
  const second = await context.getCompressedOverlay("arm9", ARM9_OVERLAY_ID);

  assert.strictEqual(second, first);
  assert.equal(context.decodedBytesCharged, pair.decoded.length);
});

test("compressed runtime context enforces stored and decoded limits", async () => {
  const { map, pair, arm9Backing } = await createCompressedRuntimeFixture();

  const storedLimit: Partial<NdsOverlayRuntimeLimits> = {
    maxStoredBytes: arm9Backing.length - 1,
  };
  await expectCategory(
    () => createNdsOverlayRuntimeContext(map, storedLimit)
      .getCompressedOverlay("arm9", ARM9_OVERLAY_ID),
    "blz-output-limit",
  );

  const decodedLimit: Partial<NdsOverlayRuntimeLimits> = {
    maxDecodedBytes: pair.decoded.length - 1,
  };
  await expectCategory(
    () => createNdsOverlayRuntimeContext(map, decodedLimit)
      .getCompressedOverlay("arm9", ARM9_OVERLAY_ID),
    "blz-output-limit",
  );
});

test("compressed runtime context enforces aggregate decoded bytes across unique overlays", async () => {
  const { map, pair } = await createCompressedRuntimeFixture();
  const context = createNdsOverlayRuntimeContext(map, {
    maxAggregateDecodedBytes: pair.decoded.length * 2 - 1,
  });

  await context.getCompressedOverlay("arm9", ARM9_OVERLAY_ID);
  assert.equal(context.decodedBytesCharged, pair.decoded.length);
  await expectCategory(
    () => context.getCompressedOverlay("arm7", ARM7_OVERLAY_ID),
    "blz-output-limit",
  );
  assert.equal(context.decodedBytesCharged, pair.decoded.length);
});

test("compressed runtime service rejects a ROM changed after canonical mapping", async () => {
  const { map, fixture } = await createCompressedRuntimeFixture();
  fixture.buffer[0x100] = fixture.buffer[0x100]! ^ 0xff;
  await writeFile(fixture.romPath, fixture.buffer);

  await expectCategory(
    () => createNdsOverlayRuntimeContext(map)
      .getCompressedOverlay("arm9", ARM9_OVERLAY_ID),
    "invalid-rom",
  );
});

test("compressed runtime service never returns a cached image after source mutation", async () => {
  const { map, fixture } = await createCompressedRuntimeFixture();
  const context = createNdsOverlayRuntimeContext(map);
  await context.getCompressedOverlay("arm9", ARM9_OVERLAY_ID);

  fixture.buffer[0x101] = fixture.buffer[0x101]! ^ 0xff;
  await writeFile(fixture.romPath, fixture.buffer);

  await expectCategory(
    () => context.getCompressedOverlay("arm9", ARM9_OVERLAY_ID),
    "invalid-rom",
  );
});
