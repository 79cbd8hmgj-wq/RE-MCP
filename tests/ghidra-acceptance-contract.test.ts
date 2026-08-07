import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import test from "node:test";

const root = fileURLToPath(new URL("../", import.meta.url));
const scriptPath = path.join(root, "scripts", "ghidra-acceptance.mjs");
const workflowPath = path.join(root, ".github", "workflows", "ghidra-integration.yml");

async function readableText(filePath: string): Promise<string | null> {
  try {
    return await readFile(filePath, "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw error;
  }
}

test("manual real-Ghidra acceptance harness is standalone, synthetic-only, and checks analyst preservation", async () => {
  const source = await readableText(scriptPath);
  assert.notEqual(source, null, "scripts/ghidra-acceptance.mjs must exist");
  assert.match(source!, /<relative-rom-path>/);
  assert.match(source!, /Buffer\.alloc\s*\(/);
  assert.match(source!, /writeSyntheticRom\s*\(/);
  assert.match(source!, /writeOverlayRecord/);
  assert.match(source!, /RE_MCP_ARM9_OVL_1/);
  assert.match(source!, /RE_MCP_ARM9_OVL_2/);
  assert.match(source!, /not-imported-compressed|compressedOverlayIds/);
  assert.match(source!, /REMCP_ACCEPTANCE_ANALYST_MARKER/);
  assert.match(source!, /createLabel\s*\(/);
  assert.match(source!, /SourceType\.USER_DEFINED/);
  assert.match(source!, /getGlobalSymbol\s*\(/);
  assert.match(source!, /ARM:LE:32:v5t/);
  assert.match(source!, /ARM:LE:32:v4t/);
  assert.match(source!, /functionEnd|bodyEnd|bodySize/);
  assert.doesNotMatch(source!, /Bakugan\.nds|Pokemon|private ROM/i);
});

test("real-Ghidra acceptance workflow is manual-only and pins release identity", async () => {
  const source = await readableText(workflowPath);
  assert.notEqual(source, null, ".github/workflows/ghidra-integration.yml must exist");
  assert.match(source!, /workflow_dispatch:/);
  assert.doesNotMatch(source!, /^\s*(push|pull_request):/mu);
  assert.match(source!, /java-version:\s*['"]?21['"]?/);
  assert.match(source!, /Ghidra_12\.1\.2_build/);
  assert.match(source!, /ghidra_12\.1\.2_PUBLIC_20260605\.zip/);
  assert.match(source!, /b62e81a0390618466c019c60d8c2f796ced2509c4c1aea4a37644a77272cf99d/);
  assert.match(source!, /sha256sum\s+(?:-c|--check)/);
  assert.match(source!, /--strict/);
  assert.match(source!, /ghidra-acceptance\.mjs/);
  assert.match(source!, /fixture\.nds/);
});
