import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import test from "node:test";

const preparePath = fileURLToPath(new URL("../resources/ghidra/ReMcpPrepareProgram.java", import.meta.url));

async function source(): Promise<string> {
  return readFile(preparePath, "utf8");
}

test("Ghidra bootstrap marks every RE-MCP-proven function entry as an analysis entry point without inventing a function body", async () => {
  const text = await source();
  assert.match(text, /SymbolTable/);
  assert.match(text, /addExternalEntryPoint\s*\(/,
    "proven RE-MCP entries must seed normal Ghidra auto-analysis");
  assert.match(text, /isExternalEntryPoint\s*\(/,
    "reruns should check the existing entry-point marker before adding it");
  assert.match(text, /identityAddress\s*\(\s*entry\s*,\s*overlaySpaces\s*\)/,
    "entry-point seeding must use the same canonical main/overlay identity resolver as proven mode context");

  assert.doesNotMatch(text, /createFunction\s*\(/,
    "RE-MCP proves an entry, not a Ghidra function body");
  assert.doesNotMatch(text, /CreateFunctionCmd/u,
    "bootstrap must not ask Ghidra to synthesize a function body directly");
  assert.doesNotMatch(text, /removeExternalEntryPoint\s*\(/,
    "bootstrap must not delete analyst/Ghidra entry-point state");
});
