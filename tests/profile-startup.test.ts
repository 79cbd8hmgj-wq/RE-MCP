import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const HEAVY_TOOL_MODULES = [
  "./tools/bakugan.js",
  "./tools/desmume.js",
  "./tools/nds-functions.js",
  "./tools/nds-ghidra.js",
  "./tools/nds-mutation.js",
  "./tools/nds-runtime.js",
  "./tools/nds.js",
  "./tools/nds-pattern.js",
  "./tools/re-orchestration.js",
  "./tools/runtime-evidence.js",
] as const;

test("focused startup does not statically import tool-family modules", async () => {
  const source = await readFile(new URL("../src/index.ts", import.meta.url), "utf8");

  for (const specifier of HEAVY_TOOL_MODULES) {
    const escaped = specifier.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
    const staticImport = new RegExp(
      `^import(?:[\\s\\S]*?from\\s+)?["']${escaped}["'];`,
      "mu",
    );
    assert.equal(
      staticImport.test(source),
      false,
      `${specifier} must be loaded conditionally after the active profile is known`,
    );
  }
});

test("startup keeps full-profile compatibility while gating family loading by the active profile", async () => {
  const source = await readFile(new URL("../src/index.ts", import.meta.url), "utf8");

  assert.match(source, /TOOL_PROFILES\[activeToolProfile\]/u);
  assert.match(source, /await import\("\.\/tools\/nds\.js"\)/u);
  assert.match(source, /await import\("\.\/tools\/re-orchestration\.js"\)/u);
  assert.match(source, /await import\("\.\/tools\/desmume\.js"\)/u);
});
