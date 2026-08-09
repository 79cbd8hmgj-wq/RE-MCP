import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

test("install verifier exercises packaged compressed-overlay bundle generation", async () => {
  const source = await readFile(path.resolve("scripts/check-install.mjs"), "utf8");
  for (const required of [
    "dist/services/nds/blz.js",
    "dist/services/nds/overlay-runtime.js",
    "dist/services/nds/extraction.js",
    "extractNdsAnalysisBundle",
    "runtimeArtifacts",
    "runtime/overlays",
    "derived-blz",
  ]) {
    assert.equal(source.includes(required), true, required);
  }
});
