import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import test from "node:test";

const resourceRoot = fileURLToPath(new URL("../resources/ghidra/", import.meta.url));

async function source(name: string): Promise<string> {
  return await readFile(path.join(resourceRoot, name), "utf8");
}

test("Ghidra preparation accepts only owned v1/v2 bridge identities and migrates ownership after reconciliation", async () => {
  const prepare = await source("ReMcpPrepareProgram.java");

  assert.match(prepare, /BRIDGE_FORMAT_VERSION\s*=\s*2/);
  assert.match(prepare, /re-mcp-nds-ghidra:1/);
  assert.match(prepare, /re-mcp-nds-ghidra:2/);
  assert.match(prepare, /existing.*bridge-format|bridge-format.*existing/is);
  assert.doesNotMatch(prepare, /validateOwnedValue\s*\(\s*info\s*,\s*KEY_BRIDGE_FORMAT/u,
    "v1 projects require an explicit bounded migration path rather than exact-v2 rejection");

  const reconcileIndex = prepare.indexOf("reconcileOverlays(");
  const bridgeWriteIndex = prepare.indexOf("info.setString(KEY_BRIDGE_FORMAT");
  assert.ok(reconcileIndex >= 0 && bridgeWriteIndex >= 0 && reconcileIndex < bridgeWriteIndex,
    "bridge-format v2 ownership may only be written after overlay reconciliation succeeds");
});

test("Ghidra preparation imports both stored and derived overlays using manifest initializedSize", async () => {
  const prepare = await source("ReMcpPrepareProgram.java");

  assert.match(prepare, /"importable-derived"/);
  assert.match(prepare, /"importable"/);
  assert.doesNotMatch(prepare, /not-imported-compressed/);
  assert.match(prepare, /requireString\s*\(\s*overlay\s*,\s*"representation"\s*\)/);
  assert.match(prepare, /requireNonNegativeLong\s*\(\s*overlay\s*,\s*"initializedSize"\s*\)/);
  assert.match(prepare, /requireString\s*\(\s*overlay\s*,\s*"runtimeSha256"\s*\)/);
  assert.match(prepare, /"rom-file-backed"/);
  assert.match(prepare, /"derived-blz"/);
  assert.doesNotMatch(prepare, /Math\.min\s*\(\s*ramSize\s*,\s*fileBackedSize\s*\)/,
    "bridge v2 declares the exact initialized byte count imported into Ghidra");
  assert.match(prepare, /resolveGeneratedArtifact\s*\(/);
  assert.match(prepare, /createInitializedBlock\s*\(/);
  assert.match(prepare, /createUninitializedBlock\s*\(/);
});

test("Ghidra overlay ownership validates actual initialized memory bytes before recording v2 metadata", async () => {
  const prepare = await source("ReMcpPrepareProgram.java");

  assert.equal(prepare.includes("re-mcp.overlay."), true);
  assert.equal(prepare.includes(".representation"), true);
  assert.equal(prepare.includes(".runtime-sha256"), true);
  assert.match(prepare, /MessageDigest\.getInstance\s*\(\s*"SHA-256"\s*\)/);
  assert.match(prepare, /getBytes\s*\(/,
    "existing Ghidra memory bytes must be hashed rather than trusting geometry alone");
  assert.match(prepare, /runtimeSha256/);
  assert.match(prepare, /representation/);

  for (const destructive of [
    /removeBlock\s*\(/,
    /deleteBlock\s*\(/,
    /clearListing\s*\(/,
    /removeFunction\s*\(/,
    /removeSymbol\s*\(/,
  ]) {
    assert.doesNotMatch(prepare, destructive);
  }
});

test("Ghidra analysis result treats compressed overlays as imported and revalidates v2 geometry", async () => {
  const record = await source("ReMcpRecordAnalysis.java");

  assert.match(record, /BRIDGE_FORMAT_VERSION\s*=\s*2/);
  assert.match(record, /"importable-derived"/);
  assert.doesNotMatch(record, /not-imported-compressed/);
  assert.match(record, /"compressed"/);
  assert.match(record, /"initializedSize"/);
  assert.match(record, /"runtimeSha256"/);
  assert.doesNotMatch(record, /fileBackedSize/);
  assert.match(record, /getBytes\s*\(/,
    "complete analysis must validate actual imported runtime bytes before emitting success");
});
