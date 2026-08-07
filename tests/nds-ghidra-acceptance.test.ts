import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import test from "node:test";

const acceptancePath = fileURLToPath(new URL("../scripts/ghidra-acceptance.mjs", import.meta.url));
const workflowPath = fileURLToPath(new URL("../.github/workflows/ghidra-integration.yml", import.meta.url));

const GHIDRA_URL = "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.2_build/ghidra_12.1.2_PUBLIC_20260605.zip";
const GHIDRA_SHA256 = "b62e81a0390618466c019c60d8c2f796ced2509c4c1aea4a37644a77272cf99d";

test("manual Ghidra acceptance workflow is dispatch-only and pins the verified 12.1.2 toolchain", async () => {
  const workflow = await readFile(workflowPath, "utf8");
  assert.match(workflow, /workflow_dispatch\s*:/);
  assert.doesNotMatch(workflow, /^\s*pull_request\s*:/m);
  assert.doesNotMatch(workflow, /^\s*push\s*:/m);
  assert.equal(workflow.includes(GHIDRA_URL), true);
  assert.equal(workflow.includes(GHIDRA_SHA256), true);
  assert.match(workflow, /java-version:\s*['"]?21['"]?/);
  assert.match(workflow, /sha256sum\s+(?:-c|--check)/);
  assert.match(workflow, /--strict/);
  assert.match(workflow, /scripts\/ghidra-acceptance\.mjs/);
  assert.match(workflow, /fixture\.nds/);
});

test("manual Ghidra acceptance uses only a synthetic NDS and checks project/evidence preservation", async () => {
  const source = await readFile(acceptancePath, "utf8");
  assert.match(source, /Buffer\.alloc\s*\(/);
  assert.match(source, /writeSyntheticRom\s*\(/);
  assert.match(source, /dist["'],\s*["']src/);
  assert.match(source, /services["'],\s*["']nds["'],\s*["']ghidra-project\.js/);
  assert.match(source, /writeOverlayRecord/);
  assert.match(source, /RE_MCP_ARM9_OVL_1/);
  assert.match(source, /RE_MCP_ARM9_OVL_2/);
  assert.match(source, /not-imported-compressed|compressedOverlayIds/);
  assert.match(source, /ARM:LE:32:v5t/);
  assert.match(source, /ARM:LE:32:v4t/);
  assert.match(source, /0x02000008[\s\S]{0,80}["']thumb["']/);
  assert.match(source, /re-mcp\.function-mode/);
  assert.match(source, /REMCP_ACCEPTANCE_ANALYST_MARKER/);
  assert.match(source, /SourceType\.USER_DEFINED/);
  assert.match(source, /createLabel\s*\(/);
  assert.match(source, /already-current/);
  assert.match(source, /bodyEnd|functionEnd|bodySize/);
  assert.doesNotMatch(source, /\.nds["']\s*\)\s*\.download|private ROM/i);
});
