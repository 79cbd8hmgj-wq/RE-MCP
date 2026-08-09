import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

async function source(relative: string): Promise<string> {
  return await readFile(new URL(`../${relative}`, import.meta.url), "utf8");
}

test("index registers the controlled mutation tool surface", async () => {
  const index = await source("src/index.ts");
  assert.match(index, /registerNdsMutationTools/);
  assert.match(index, /registerNdsMutationTools\(server, config\)/);
});

test("capability policy advertises the narrow manifest-driven write boundary", async () => {
  const index = await source("src/index.ts");
  assert.match(index, /controlled.*manifest-driven.*NDS.*build/iu);
  assert.match(index, /source ROMs? remain immutable/iu);
  assert.match(index, /same-size/iu);
  assert.match(index, /no arbitrary ROM offsets?/iu);
  assert.match(index, /no.*caller.*output paths?/iu);
  assert.doesNotMatch(index, /no ROM writes/iu);
  for (const tool of [
    "nds_mutation_validate",
    "nds_mutation_build",
    "nds_mutation_verify",
  ]) {
    assert.match(index, new RegExp(tool, "u"));
  }
});
