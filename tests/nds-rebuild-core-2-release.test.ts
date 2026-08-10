import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

async function source(relative: string): Promise<string> {
  return await readFile(new URL(`../${relative}`, import.meta.url), "utf8");
}

test("package smoke exercises the shipped v2 rebuild surface", async () => {
  const install = await source("scripts/check-nds-mutation-install.mjs");

  for (const requiredModule of [
    "dist/services/nds/blz-encode.js",
    "dist/services/nds/header-rebuild.js",
    "dist/services/nds/mutation/filesystem-plan.js",
    "dist/services/nds/mutation/layout-plan.js",
    "dist/services/nds/mutation/header-plan.js",
    "dist/services/nds/mutation/build.js",
  ]) {
    assert.match(install, new RegExp(requiredModule.replaceAll("/", "\\/"), "u"));
  }

  assert.match(install, /formatVersion:\s*2/u);
  assert.match(install, /replace-nitrofs-file/u);
  assert.match(install, /add-nitrofs-file/u);
  assert.match(install, /rebuildSemanticsVerified/u);
  assert.match(install, /rebuildContractVersion/u);
  assert.match(install, /blzEncoderContractVersion/u);
  assert.match(install, /encodeNdsBlz/u);
  assert.match(install, /decodeNdsBlz/u);
});

test("README documents Rebuild Core 2 capabilities and safety boundary", async () => {
  const readme = await source("README.md");

  assert.match(readme, /NDS Rebuild Core 2/iu);
  assert.match(readme, /variable-size NitroFS/iu);
  assert.match(readme, /add(?:ing)? new NitroFS files?/iu);
  assert.match(readme, /decoded compressed-overlay/iu);
  assert.match(readme, /BLZ recompression/iu);
  assert.match(readme, /append-only/iu);
  assert.match(readme, /FAT\/FNT/iu);
  assert.match(readme, /device capacity/iu);
  assert.match(readme, /rebuildSemanticsVerified/u);
  assert.match(readme, /source ROM.*immutable/iu);
  assert.match(readme, /arbitrary ROM offset/iu);
  assert.match(readme, /caller-selected output paths?/iu);
  assert.match(readme, /DeSmuME.*acceptance.*separate/iu);

  assert.doesNotMatch(
    readme,
    /Milestone 1 deliberately does \*\*not\*\* provide variable-size rebuilding/iu,
  );
});
