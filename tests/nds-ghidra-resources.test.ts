import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import test from "node:test";

const resourceRoot = fileURLToPath(new URL("../resources/ghidra/", import.meta.url));

const SCRIPTS = [
  "ReMcpPrepareProgram.java",
  "ReMcpImportEvidence.java",
  "ReMcpRecordAnalysis.java",
] as const;

async function sources(): Promise<Record<(typeof SCRIPTS)[number], string>> {
  const entries = await Promise.all(
    SCRIPTS.map(async (name) => [name, await readFile(path.join(resourceRoot, name), "utf8")] as const),
  );
  return Object.fromEntries(entries) as Record<(typeof SCRIPTS)[number], string>;
}

test("Ghidra resource contract never deletes or overwrites analyst-owned objects", async () => {
  const loaded = await sources();
  for (const name of SCRIPTS) {
    const source = loaded[name];
    assert.doesNotMatch(source, /clearListing|removeFunction|removeSymbol|deleteAll|clearAll/);
    assert.doesNotMatch(source, /createFunction\s*\(/);
    assert.doesNotMatch(source, /Runtime\.getRuntime|ProcessBuilder|java\.net\.|Socket\s*\(/);
  }
});

test("Ghidra resource contract enforces exact script argument counts", async () => {
  const loaded = await sources();
  assert.match(loaded["ReMcpPrepareProgram.java"], /getScriptArgs\(\)/);
  assert.match(loaded["ReMcpPrepareProgram.java"], /args\.length\s*!=\s*2/);
  assert.match(loaded["ReMcpImportEvidence.java"], /getScriptArgs\(\)/);
  assert.match(loaded["ReMcpImportEvidence.java"], /args\.length\s*!=\s*2/);
  assert.match(loaded["ReMcpRecordAnalysis.java"], /getScriptArgs\(\)/);
  assert.match(loaded["ReMcpRecordAnalysis.java"], /args\.length\s*!=\s*3/);
});

test("Ghidra resource contract contains every RE-MCP-owned metadata key", async () => {
  const joined = Object.values(await sources()).join("\n");
  for (const key of [
    "re-mcp.bridge-format",
    "re-mcp.rom-sha256",
    "re-mcp.manifest-sha256",
    "re-mcp.processor",
    "re-mcp.last-import",
    "re-mcp.last-analysis-status",
    "re-mcp.ghidra-version",
    "re-mcp.function-id",
    "re-mcp.function-proof",
    "re-mcp.function-mode",
    "re-mcp.overlay-id",
    "re-mcp.call-evidence",
  ]) {
    assert.equal(joined.includes(key), true, key);
  }
});

test("Ghidra preparation contract owns exact program identity, manifest-backed overlays and proven mode context", async () => {
  const source = (await sources())["ReMcpPrepareProgram.java"];
  assert.match(source, /Program\.PROGRAM_INFO/);
  assert.match(source, /requireString\s*\(\s*processorManifest\s*,\s*"programName"\s*\)/);
  assert.match(source, /currentProgram\.setName\s*\(\s*expectedProgramName\s*\)/);
  assert.match(source, /createInitializedBlock\s*\(/);
  assert.match(source, /createUninitializedBlock\s*\(/);
  assert.match(source, /not-imported-compressed/);
  assert.match(source, /spaceName/);
  assert.match(source, /bssSize/);
  assert.match(source, /setExecute\(true\)/);
  assert.match(source, /getProgramContext\s*\(\)/);
  assert.match(source, /getRegister\s*\(\s*"TMode"\s*\)/);
  assert.match(source, /getValue\s*\(/, "reruns must inspect existing mode context before rewriting it");
  assert.match(source, /setValue\s*\(/);
  assert.match(source, /BigInteger\.ONE|BigInteger\.ZERO/);
  assert.match(
    source,
    /validateOwnedValue\s*\(\s*info\s*,\s*KEY_BRIDGE_FORMAT/u,
    "prepare must reject conflicting bridge-format ownership metadata",
  );
});

test("Ghidra evidence contract records exact entry, mode, overlay, and isolated call evidence", async () => {
  const source = (await sources())["ReMcpImportEvidence.java"];
  for (const key of [
    "re-mcp.function-id",
    "re-mcp.function-proof",
    "re-mcp.function-mode",
    "re-mcp.overlay-id",
    "re-mcp.call-evidence",
  ]) {
    assert.equal(source.includes(key), true, key);
  }
  assert.match(source, /StringPropertyMap/);
  assert.match(source, /getAddressSpace\s*\(/);
  assert.match(source, /addMemoryReference\s*\(/);
  assert.match(source, /RefType\.UNCONDITIONAL_CALL/);
  assert.match(source, /SourceType\.IMPORTED/);
  assert.match(source, /Reference\.OTHER/, "RE-MCP evidence must not occupy Ghidra's mnemonic/operand reference slot");
  assert.doesNotMatch(source, /setBody\s*\(/);
});

test("Ghidra analysis-record contract validates the declared result and writes generated state atomically", async () => {
  const source = (await sources())["ReMcpRecordAnalysis.java"];
  assert.match(source, /analysisStatus/);
  assert.match(source, /"complete"/);
  assert.match(source, /generatedResultPaths/);
  assert.match(source, /manifestSha256/);
  assert.match(source, /sourceRomSha256/);
  assert.match(source, /programName/);
  assert.match(source, /ghidraVersion/);
  assert.match(source, /normalize\s*\(\)/);
  assert.match(source, /Files\.writeString/);
  assert.match(source, /Files\.move/);
  assert.doesNotMatch(source, /analysis\/ghidra\/nds/);
});
