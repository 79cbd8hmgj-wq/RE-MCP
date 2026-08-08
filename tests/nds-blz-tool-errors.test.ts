import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import test from "node:test";

const ndsToolsPath = fileURLToPath(new URL("../src/tools/nds.ts", import.meta.url));

test("NDS tool error mapping handles every BLZ failure category", async () => {
  const source = await readFile(ndsToolsPath, "utf8");

  assert.match(source, /case\s+"malformed-blz"\s*:/u);
  assert.match(source, /case\s+"blz-output-size-mismatch"\s*:/u);
  assert.match(source, /case\s+"blz-output-limit"\s*:/u);
});
