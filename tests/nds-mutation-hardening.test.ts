import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

async function source(relative: string): Promise<string> {
  return await readFile(new URL(`../${relative}`, import.meta.url), "utf8");
}

test("mutation write ownership stays confined to apply.ts", async () => {
  const mutationDirectory = path.join(process.cwd(), "src", "services", "nds", "mutation");
  const filenames = (await readdir(mutationDirectory))
    .filter((entry) => entry.endsWith(".ts"))
    .sort();
  const files = await Promise.all(filenames.map(async (filename) => ({
    filename,
    text: await readFile(path.join(mutationDirectory, filename), "utf8"),
  })));

  const stagedWriters = files
    .filter(({ text }) => text.includes('"r+"'))
    .map(({ filename }) => filename);
  assert.deepEqual(stagedWriters, ["apply.ts"]);

  const forbiddenGenericWriter = /\b(?:writeRomBytes|patchRomOffset|replaceRomRange|writeAbsoluteOffset)\b/u;
  for (const { filename, text } of files) {
    assert.doesNotMatch(text, forbiddenGenericWriter, `${filename} exposes a generic ROM writer`);
  }
});

test("package workflow requires and exercises the controlled Rebuild Core 2 surface", async () => {
  const install = await source("scripts/check-nds-mutation-install.mjs");
  const workflow = await source(".github/workflows/package.yml");
  for (const requiredModule of [
    "dist/services/nds/blz-encode.js",
    "dist/services/nds/header-rebuild.js",
    "dist/services/nds/mutation/manifest.js",
    "dist/services/nds/mutation/planner.js",
    "dist/services/nds/mutation/filesystem-plan.js",
    "dist/services/nds/mutation/layout.js",
    "dist/services/nds/mutation/header-plan.js",
    "dist/services/nds/mutation/build.js",
    "dist/tools/nds-mutation.js",
  ]) {
    assert.match(install, new RegExp(requiredModule.replaceAll("/", "\\/"), "u"));
  }
  assert.doesNotMatch(install, /dist\/services\/nds\/mutation\/layout-plan\.js/u);
  assert.match(install, /registerNdsMutationTools\(server, config\)/u);
  assert.match(install, /loadNdsMutationManifest/u);
  assert.match(install, /buildNdsMutation/u);
  assert.match(install, /verifyPublishedNdsMutationBuild/u);
  assert.match(install, /formatVersion:\s*2/u);
  assert.match(install, /replace-nitrofs-file/u);
  assert.match(install, /add-nitrofs-file/u);
  assert.match(install, /encodeNdsBlz/u);
  assert.match(install, /decodeNdsBlz/u);
  assert.match(install, /rebuildSemanticsVerified/u);
  assert.match(install, /unexpectedChangedBytes/u);
  assert.match(install, /mutation-manifest\.json/u);
  assert.match(install, /resolved-plan\.json/u);
  assert.match(install, /verification\.json/u);
  assert.match(install, /changed-components\.json/u);
  assert.match(install, /output\.sha256/u);
  assert.match(install, /output.*nds/iu);
  assert.match(workflow, /cp -R scripts "\$root\/"/u);
  assert.match(workflow, /node scripts\/check-nds-mutation-install\.mjs \./u);
});

test("README documents NDS Rebuild Core 2 and its safety boundary", async () => {
  const readme = await source("README.md");
  assert.match(readme, /Static-analysis extraction artifacts are restricted to `analysis\/generated\/nds\/<sha-prefix>\/`/u);
  assert.doesNotMatch(readme, /Generated NDS artifacts are restricted to `analysis\/generated\/nds\/<sha-prefix>\/`/u);
  assert.match(readme, /NDS Rebuild Core 2/iu);
  for (const tool of [
    "nds_mutation_validate",
    "nds_mutation_build",
    "nds_mutation_verify",
  ]) {
    assert.match(readme, new RegExp(tool, "u"));
  }
  assert.match(readme, /source ROM.*immutable/iu);
  assert.match(readme, /same-size/iu);
  assert.match(readme, /variable-size NitroFS/iu);
  assert.match(readme, /decoded compressed-overlay/iu);
  assert.match(readme, /BLZ recompression/iu);
  assert.match(readme, /append-only/iu);
  assert.match(readme, /FAT\/FNT/iu);
  assert.match(readme, /device capacity/iu);
  assert.match(readme, /rebuildSemanticsVerified/u);
  assert.match(readme, /output\/nds\/<source-sha-prefix>\/<build-id>/u);
  for (const evidence of [
    "mutation-manifest.json",
    "resolved-plan.json",
    "verification.json",
    "changed-components.json",
    "output.sha256",
  ]) {
    assert.match(readme, new RegExp(evidence.replace(".", "\\."), "u"));
  }
  assert.match(readme, /arbitrary ROM offset/iu);
  assert.match(readme, /caller-selected output paths?/iu);
  assert.match(readme, /DeSmuME.*acceptance.*separate/iu);
  assert.doesNotMatch(
    readme,
    /Milestone 1 deliberately does \*\*not\*\* provide variable-size rebuilding/iu,
  );
});