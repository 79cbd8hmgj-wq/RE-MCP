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
