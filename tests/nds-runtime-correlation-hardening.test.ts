import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

async function source(relative: string): Promise<string> {
  return await readFile(new URL(`../${relative}`, import.meta.url), "utf8");
}

test("install verifier requires packaged runtime correlation and Ghidra adapter surfaces", async () => {
  const install = await source("scripts/check-install.mjs");
  assert.match(install, /dist\/services\/nds\/runtime-correlation\.js/);
  assert.match(install, /dist\/services\/nds\/runtime-correlation-ghidra\.js/);
  assert.match(install, /dist\/tools\/nds-runtime\.js/);
  assert.match(install, /registerNdsRuntimeTools\(server, config, desmumeManager, desmumeDebugger\)/);
});

test("README documents exact-ROM stopped correlation and opt-in ready-project Ghidra enrichment", async () => {
  const readme = await source("README.md");
  assert.match(readme, /nds_correlate_stop_context/);
  assert.match(readme, /includeGhidra/);
  assert.match(readme, /decompileGhidraFunction/);
  assert.match(readme, /launch-time ROM SHA-256/);
  assert.match(readme, /already-current.*Ghidra/iu);
  assert.match(readme, /does not bootstrap.*Ghidra/iu);
  assert.match(readme, /overlapping overlay candidates/iu);
});

test("capability policy states that runtime Ghidra enrichment is opt-in and non-mutating", async () => {
  const index = await source("src/index.ts");
  assert.match(index, /current-stop.*opt-in.*already-current.*Ghidra/iu);
  assert.match(index, /no Ghidra bootstrap.*correlation/iu);
});

test("Catalina debug bundle carries the final physical runtime-correlation acceptance checklist", async () => {
  const workflow = await source(".github/workflows/build-desmume-catalina-native.yml");
  assert.match(workflow, /nds_correlate_stop_context/);
  assert.match(workflow, /launch SHA-256/);
  assert.match(workflow, /observed PC\/CPSR/);
  assert.match(workflow, /canonical candidates/);
  assert.match(workflow, /bounded static interpretation/);
  assert.match(workflow, /physical Catalina acceptance/iu);
});
