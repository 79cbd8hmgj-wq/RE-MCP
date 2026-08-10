import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import test from "node:test";

import { crc16NdsHeader } from "../src/services/nds/header-rebuild.js";
import { hashFileSha256 } from "../src/services/nds/io.js";
import { buildNdsMutation } from "../src/services/nds/mutation/build.js";
import { loadNdsMutationManifest } from "../src/services/nds/mutation/manifest.js";
import { readNdsRomMap } from "../src/services/nds/rom-map.js";
import { createMutationFixture } from "./helpers/nds-mutation-fixture.js";

function sha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

test("v2 fixed stored compressed overlay replacements retain runtime verification evidence", async () => {
  const fixture = await createMutationFixture();
  const source = await readFile(fixture.romPath);
  source.writeUInt16LE(crc16NdsHeader(source.subarray(0, 0x15e)), 0x15e);
  await writeFile(fixture.romPath, source);
  const map = await readNdsRomMap(fixture.romPath);
  const sourceSha256 = await hashFileSha256(fixture.romPath);
  const overlay = map.overlays.arm9.find(
    (candidate) => candidate.overlayId === fixture.compressedOverlayId,
  );
  assert.ok(overlay);

  const original = source.subarray(overlay.romOffset, overlay.romOffset + overlay.romSize);
  const replacement = Buffer.from(original);
  replacement[replacement.length - 1] = replacement[replacement.length - 1] === 0x5a ? 0x5b : 0x5a;
  const artifact = await fixture.writeArtifact("artifacts/v2-fixed-compressed.bin", replacement);
  const manifestPath = await fixture.writeManifest({
    formatVersion: 2,
    sourceSha256,
    outputFilename: "v2-fixed-compressed.nds",
    operations: [{
      type: "replace-component",
      target: { component: "arm9-overlay", overlayId: fixture.compressedOverlayId },
      expectedOriginalSha256: sha256(original),
      replacement: { artifact: artifact.relativePath, sha256: artifact.sha256 },
    }],
  }, "plans/v2-fixed-compressed.json");
  const loaded = await loadNdsMutationManifest(fixture.directory, manifestPath);
  const result = await buildNdsMutation(map, fixture.directory, loaded);

  assert.deepEqual(
    result.verification.compressedOverlays.map(
      (entry) => [entry.processor, entry.overlayId, entry.status],
    ),
    [["arm9", fixture.compressedOverlayId, "passed"]],
  );
  assert.match(result.verification.compressedOverlays[0]?.runtimeSha256 ?? "", /^[0-9a-f]{64}$/u);
});
