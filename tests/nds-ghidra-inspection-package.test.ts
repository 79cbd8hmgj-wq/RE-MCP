import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import test from "node:test";

test("install smoke requires the complete controlled Ghidra inspection surface", async () => {
  const checkPath = fileURLToPath(new URL("../scripts/check-ghidra-inspection-install.mjs", import.meta.url));
  const source = await readFile(checkPath, "utf8");
  for (const required of [
    "dist/services/nds/ghidra-inspection.js",
    "dist/services/nds/ghidra-inspection-readiness.js",
    "resources/ghidra/ReMcpInspectProgram.java",
    "nds_ghidra_inspect_function",
    "nds_ghidra_decompile_function",
    "nds_ghidra_search_symbols",
    "nds_ghidra_list_references",
    "nds_ghidra_list_calls",
  ]) {
    assert.equal(source.includes(required), true, required);
  }

  const workflowPath = fileURLToPath(new URL("../.github/workflows/package.yml", import.meta.url));
  const workflow = await readFile(workflowPath, "utf8");
  assert.match(workflow, /check-ghidra-inspection-install\.mjs/);
});

test("normal package workflow never downloads or requires Ghidra", async () => {
  const workflowPath = fileURLToPath(new URL("../.github/workflows/package.yml", import.meta.url));
  const source = await readFile(workflowPath, "utf8");
  assert.doesNotMatch(source, /setup-java/u);
  assert.doesNotMatch(source, /ghidra_12|Download and verify Ghidra|analyzeHeadless/u);
});
