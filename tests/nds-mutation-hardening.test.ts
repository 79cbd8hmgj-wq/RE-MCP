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

test("package workflow requires and exercises the controlled mutation core", async () => {
  const install = await source("scripts/check-nds-mutation-install.mjs");
  const workflow = await source(".github/workflows/package.yml");
  for (const requiredModule of [
    "dist/services/nds/mutation/manifest.js",
    "dist/services/nds/mutation/planner.js",
    "dist/services/nds/mutation/build.js",
    "dist/tools/nds-mutation.js",
  ]) {
    assert.match(install, new RegExp(requiredModule.replaceAll("/", "\\/"), "u"));
  }
  assert.match(install, /registerNdsMutationTools\(server, config\)/u);
  assert.match(install, /loadNdsMutationManifest/u);
  assert.match(install, /buildNdsMutation/u);
  assert.match(install, /verifyPublishedNdsMutationBuild/u);
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

test("README documents Controlled NDS Mutation Milestone 1 and its exclusions", async () => {
  const readme = await source("README.md");
  assert.match(readme, /Static-analysis extraction artifacts are restricted to `analysis\/generated\/nds\/<sha-prefix>\/`/u);
  assert.doesNotMatch(readme, /Generated NDS artifacts are restricted to `analysis\/generated\/nds\/<sha-prefix>\/`/u);
  assert.match(readme, /Controlled NDS Mutation.*Milestone 1/iu);
  for (const tool of [
    "nds_mutation_validate",
    "nds_mutation_build",
    "nds_mutation_verify",
  ]) {
    assert.match(readme, new RegExp(tool, "u"));
  }
  assert.match(readme, /source ROM.*immutable/iu);
  assert.match(readme, /same-size/iu);
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
  assert.match(readme, /variable-size/iu);
  assert.match(readme, /FAT\/FNT/iu);
  assert.match(readme, /BLZ recompression/iu);
  assert.match(readme, /arbitrary ROM offset/iu);
  assert.match(readme, /caller-selected output paths?/iu);
});