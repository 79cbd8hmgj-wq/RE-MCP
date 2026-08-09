import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import test from "node:test";

const acceptancePath = fileURLToPath(
  new URL("../scripts/ghidra-runtime-correlation-acceptance.mjs", import.meta.url),
);
const workflowPath = fileURLToPath(
  new URL("../.github/workflows/ghidra-compressed-overlay-acceptance-trigger.yml", import.meta.url),
);

test("real Ghidra runtime-correlation acceptance covers main and compressed overlay read-only", async () => {
  const source = await readFile(acceptancePath, "utf8");
  assert.match(source, /correlateNdsStopContext/);
  assert.match(source, /createRuntimeGhidraEnricher/);
  assert.match(source, /createCapstoneArmBackend/);
  assert.match(source, /runtimeAddress|0x02000000/);
  assert.match(source, /0x02210000/);
  assert.match(source, /overlayId.*3|overlay 3/iu);
  assert.match(source, /includeGhidra:\s*true/);
  assert.match(source, /decompileGhidraFunction:\s*true/);
  assert.match(source, /derived-overlay/);
  assert.match(source, /romOffset/);
  assert.match(source, /snapshotProject/);
  assert.match(source, /read-only runtime correlation changed persistent project bytes/);
  assert.match(source, /source ROM changed during runtime correlation acceptance/);
  assert.match(source, /ghidraDerived/);
  assert.doesNotMatch(source, /bootstrapNdsGhidraProject|reconcile/iu);
});

test("PR B real-Ghidra workflow runs runtime-correlation acceptance on the feature branch", async () => {
  const workflow = await readFile(workflowPath, "utf8");
  assert.match(workflow, /feature\/nds-runtime-correlation-ghidra/);
  assert.match(workflow, /java-version:\s*['"]?21['"]?/);
  assert.match(workflow, /ghidra_12\.1\.2_PUBLIC/);
  assert.match(workflow, /scripts\/ghidra-runtime-correlation-acceptance\.mjs/);
  assert.match(workflow, /Run real Ghidra runtime correlation acceptance/);
});
