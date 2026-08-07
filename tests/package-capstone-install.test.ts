import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

test("install verifier requires packaged Capstone JavaScript and WASM assets", async () => {
  const source = await readFile(
    path.resolve("scripts/check-install.mjs"),
    "utf8",
  );
  for (const required of [
    "node_modules/@alexaltea/capstone-js/package.json",
    "node_modules/@alexaltea/capstone-js/dist/capstone.js",
    "node_modules/@alexaltea/capstone-js/dist/capstone.wasm",
  ]) {
    assert.equal(source.includes(required), true, required);
  }
});

test("install verifier initializes the packaged adapter and smoke-decodes ARM and Thumb", async () => {
  const source = await readFile(
    path.resolve("scripts/check-install.mjs"),
    "utf8",
  );
  assert.equal(source.includes("createCapstoneArmBackend"), true);
  assert.equal(source.includes("Packaged Capstone ARM smoke decode failed"), true);
  assert.equal(source.includes("Packaged Capstone Thumb smoke decode failed"), true);
  assert.equal(source.includes("dist/services/disassembly/capstone.js"), true);
});

test("install verifier smoke-classifies packaged ARM and Thumb references", async () => {
  const source = await readFile(
    path.resolve("scripts/check-install.mjs"),
    "utf8",
  );
  assert.equal(source.includes("dist/services/nds/disassembly.js"), true);
  assert.equal(source.includes("dist/services/nds/references.js"), true);
  assert.equal(source.includes("Packaged ARM direct reference smoke failed"), true);
  assert.equal(source.includes("Packaged Thumb PC-relative reference smoke failed"), true);
});

test("install verifier smoke-searches packaged NDS patterns", async () => {
  const source = await readFile(
    path.resolve("scripts/check-install.mjs"),
    "utf8",
  );
  for (const required of [
    "dist/services/nds/pattern-search.js",
    "dist/services/nds/rom-map.js",
    "Packaged NDS pattern overlap smoke failed",
    "Packaged NDS pattern ownership smoke failed",
  ]) {
    assert.equal(source.includes(required), true, required);
  }
});

test("package workflow labels the assembled-bundle smoke acceptance explicitly", async () => {
  const source = await readFile(
    path.resolve(".github/workflows/package.yml"),
    "utf8",
  );
  assert.equal(
    source.includes("Assemble and smoke-test self-contained bundle"),
    true,
  );
  assert.equal(source.includes("npm install --omit=dev --ignore-scripts"), true);
  assert.equal(source.includes("node scripts/check-install.mjs ."), true);
});
