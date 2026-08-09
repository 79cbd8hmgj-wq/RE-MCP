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
    "re-mcp.overlay.",
    ".representation",
    ".runtime-sha256",
  ]) {
    assert.equal(joined.includes(key), true, key);
  }
});

test("Ghidra preparation contract owns exact program identity, v2 overlays and proven mode context", async () => {
  const source = (await sources())["ReMcpPrepareProgram.java"];
  assert.match(source, /BRIDGE_FORMAT_VERSION\s*=\s*2/);
  assert.match(source, /Program\.PROGRAM_INFO/);
  assert.match(source, /requireString\s*\(\s*processorManifest\s*,\s*"programName"\s*\)/);
  assert.match(source, /currentProgram\.setName\s*\(\s*expectedProgramName\s*\)/);
  assert.match(source, /createInitializedBlock\s*\(/);
  assert.match(source, /createUninitializedBlock\s*\(/);
  assert.match(source, /importable-derived/);
  assert.doesNotMatch(source, /not-imported-compressed/);
  assert.match(source, /representation/);
  assert.match(source, /initializedSize/);
  assert.match(source, /runtimeSha256/);
  assert.match(source, /getBytes\s*\(/,
    "reruns and v1 migration must validate actual initialized overlay bytes");
  assert.match(source, /spaceName/);
  assert.match(source, /bssSize/);
  assert.match(source, /getAddressInThisSpaceOnly\s*\(\s*bssOffset\s*\)/,
    "BSS beyond the initialized overlay region must stay in the existing overlay address space");
  assert.match(source, /isInitialized\s*\(\)/,
    "initialized overlay blocks and uninitialized BSS must be distinguished explicitly");
  assert.match(source, /setExecute\(true\)/);
  assert.match(source, /getProgramContext\s*\(\)/);
  assert.match(source, /getRegister\s*\(\s*"TMode"\s*\)/);
  assert.match(source, /getValue\s*\(/, "reruns must inspect existing mode context before rewriting it");
  assert.match(source, /setValue\s*\(/);
  assert.match(source, /BigInteger\.ONE|BigInteger\.ZERO/);
  assert.match(source, /re-mcp-nds-ghidra:1/,
    "v1 project ownership must have an explicit bounded migration path");
  assert.match(source, /re-mcp-nds-ghidra:2/);
});

test("Ghidra evidence contract records exact entry, mode, overlay, and call evidence without inventing Ghidra flow semantics", async () => {
  const source = (await sources())["ReMcpImportEvidence.java"];
  assert.match(source, /BRIDGE_FORMAT_VERSION\s*=\s*2/);
  assert.match(source, /importable-derived/);
  assert.doesNotMatch(source, /not-imported-compressed/);
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
  assert.match(source, /callEvidence\.add\s*\(/,
    "exact RE-MCP direct-call evidence must remain attached to its source address");
  assert.doesNotMatch(source, /addMemoryReference\s*\(/,
    "the retained call edge does not prove conditional vs unconditional Ghidra flow type");
  assert.doesNotMatch(source, /RefType\./,
    "Ghidra flow-reference typing must be left to Ghidra auto-analysis");
  assert.doesNotMatch(source, /SourceType\./,
    "RE-MCP must not pre-create Ghidra-derived flow references");
  assert.doesNotMatch(source, /setBody\s*\(/);
});

test("Ghidra analysis-record contract validates the declared v2 result and writes generated state atomically", async () => {
  const source = (await sources())["ReMcpRecordAnalysis.java"];
  assert.match(source, /BRIDGE_FORMAT_VERSION\s*=\s*2/);
  assert.match(source, /analysisStatus/);
  assert.match(source, /"complete"/);
  assert.match(source, /generatedResultPaths/);
  assert.match(source, /manifestSha256/);
  assert.match(source, /sourceRomSha256/);
  assert.match(source, /programName/);
  assert.match(source, /ghidraVersion/);
  assert.match(source, /importable-derived/);
  assert.match(source, /validateImportedOverlay\s*\(/,
    "recording complete analysis must revalidate every manifest-declared imported overlay");
  assert.match(source, /MemoryBlock/);
  assert.match(source, /isOverlay\s*\(\)/);
  assert.match(source, /isInitialized\s*\(\)/);
  assert.match(source, /getBytes\s*\(/);
  assert.match(source, /runtimeSha256/);
  assert.match(source, /getAddressSpace\s*\(\)\.getName\s*\(\)/);
  assert.match(source, /normalize\s*\(\)/);
  assert.match(source, /Files\.writeString/);
  assert.match(source, /Files\.move/);
  assert.doesNotMatch(source, /analysis\/ghidra\/nds/);
});
