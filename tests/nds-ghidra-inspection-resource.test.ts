import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import test from "node:test";

const scriptPath = fileURLToPath(new URL("../resources/ghidra/ReMcpInspectProgram.java", import.meta.url));

async function source(): Promise<string> {
  return readFile(scriptPath, "utf8");
}

test("Ghidra inspection resource validates its fixed request envelope and program ownership", async () => {
  const text = await source();
  assert.match(text, /getScriptArgs\(\)/);
  assert.match(text, /args\.length\s*!=\s*2/);
  assert.match(text, /re-mcp-nds-ghidra-inspection/);
  assert.match(text, /formatVersion/);
  assert.match(text, /Program\.PROGRAM_INFO/);
  assert.match(text, /re-mcp\.rom-sha256/);
  assert.match(text, /re-mcp\.processor/);
  assert.match(text, /programName/);
  assert.match(text, /requestId/);
});

test("Ghidra inspection resource resolves main through the real default space and overlays by explicit owned space", async () => {
  const text = await source();
  assert.match(text, /getDefaultAddressSpace\s*\(\)/);
  assert.match(text, /getAddressSpace\s*\(/);
  assert.match(text, /isOverlaySpace\s*\(\)/);
  assert.match(text, /runtimeAddress/);
  assert.match(text, /addressSpace/);
});

test("Ghidra inspection resource emits explicit default and overlay address-space identity", async () => {
  const text = await source();
  assert.match(text, /private JsonObject addressObject\s*\(Address address\)/);
  assert.match(text, /AddressSpace space\s*=\s*address\.getAddressSpace\(\)/);
  assert.match(text, /AddressSpace defaultSpace\s*=\s*currentProgram\.getAddressFactory\(\)\.getDefaultAddressSpace\(\)/);
  assert.match(text, /addProperty\("overlaySpace",\s*space\.isOverlaySpace\(\)\)/);
  assert.match(text, /addProperty\("defaultSpace",\s*space\.equals\(defaultSpace\)\)/);
});

test("Ghidra inspection resource reads function and RE-MCP metadata without claiming function bodies as canonical", async () => {
  const text = await source();
  assert.match(text, /FunctionManager/);
  assert.match(text, /getFunctionContaining\s*\(/);
  assert.match(text, /getBody\s*\(\)/);
  assert.match(text, /getAddressRanges\s*\(\)/);
  assert.match(text, /256/);
  assert.match(text, /StringPropertyMap/);
  assert.match(text, /re-mcp\.function-id/);
  assert.match(text, /re-mcp\.function-proof/);
  assert.match(text, /re-mcp\.function-mode/);
  assert.match(text, /re-mcp\.overlay-id/);
});

test("Ghidra inspection resource decompiles exactly one existing function with a 30 second bound", async () => {
  const text = await source();
  assert.match(text, /DecompInterface/);
  assert.match(text, /openProgram\s*\(/);
  assert.match(text, /decompileFunction\s*\([^,]+,\s*30\s*,/s);
  assert.match(text, /decompileCompleted\s*\(\)/);
  assert.match(text, /getDecompiledFunction\s*\(\)/);
  assert.match(text, /getC\s*\(\)/);
  assert.match(text, /dispose\s*\(\)/);
  assert.match(text, /maxCharacters/);
  assert.match(text, /100000/);
});

test("Ghidra inspection resource supports bounded symbol reference and depth-one call inspection", async () => {
  const text = await source();
  assert.match(text, /SymbolTable/);
  assert.match(text, /getAllSymbols\s*\(\s*true\s*\)/);
  assert.match(text, /ReferenceManager/);
  assert.match(text, /getReferencesFrom\s*\(/);
  assert.match(text, /getReferencesTo\s*\(/);
  assert.match(text, /isCall\s*\(\)/);
  assert.match(text, /search-symbols/);
  assert.match(text, /list-references/);
  assert.match(text, /list-calls/);
  assert.match(text, /re-mcp\.call-evidence/);
  assert.match(text, /exact/);
  assert.match(text, /prefix/);
  assert.match(text, /contains/);
  assert.match(text, /callers/);
  assert.match(text, /callees/);
  assert.match(text, /1000/);
  assert.match(text, /100000/);
});

test("Ghidra inspection resource writes only its generated result and contains no project mutation surface", async () => {
  const text = await source();
  assert.match(text, /Files\.writeString/);
  assert.match(text, /Files\.move/);
  assert.match(text, /ATOMIC_MOVE/);

  for (const forbidden of [
    /createFunction\s*\(/,
    /removeFunction\s*\(/,
    /createThunkFunction\s*\(/,
    /setBody\s*\(/,
    /addMemoryReference\s*\(/,
    /removeAllReferences/u,
    /createInitializedBlock\s*\(/,
    /createUninitializedBlock\s*\(/,
    /deleteBlock\s*\(/,
    /setValue\s*\(/,
    /setName\s*\(/,
    /setComment\s*\(/,
    /createLabel\s*\(/,
    /createBookmark\s*\(/,
    /Runtime\.getRuntime/u,
    /ProcessBuilder/u,
    /java\.net\./u,
    /Socket\s*\(/,
  ]) {
    assert.doesNotMatch(text, forbidden);
  }
});
