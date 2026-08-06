import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const workflowPath = new URL(
  "../.github/workflows/build-desmume-catalina-native.yml",
  import.meta.url,
);
const patchPath = new URL(
  "../scripts/patch-desmume-catalina-native.py",
  import.meta.url,
);

async function read(path: URL): Promise<string> {
  return await readFile(path, "utf8");
}

test("Catalina workflow is manual-only", async () => {
  const workflow = await read(workflowPath);
  assert.match(workflow, /workflow_dispatch:/);
  assert.doesNotMatch(workflow, /pull_request:/);
  assert.doesNotMatch(workflow, /\bpush:/);
});

test("Catalina workflow pins Intel source and target", async () => {
  const workflow = await read(workflowPath);
  assert.match(workflow, /release_0_9_13/);
  assert.match(workflow, /DeSmuME \(macOS App; Intel64 dev\+ -- Latest Xcode\)/);
  assert.match(workflow, /ARCHS=x86_64/);
  assert.match(workflow, /MACOSX_DEPLOYMENT_TARGET=10\.15/);
  assert.match(workflow, /CODE_SIGNING_ALLOWED=NO/);
});

test("Catalina patch disables Metal guards in the three failing translation units", async () => {
  const patch = await read(patchPath);
  assert.match(patch, /DisplayWindowController\.mm/);
  assert.match(patch, /cocoa_GPU\.mm/);
  assert.match(patch, /MacScreenshotCaptureTool\.mm/);
  assert.match(patch, /RE_MCP_CATALINA_USE_METAL/);
  assert.match(patch, /replace_metal_guards/);
  assert.match(patch, /expected at least one ENABLE_APPLE_METAL guard/);
});

test("Catalina workflow rejects remaining Metal compilation or symbols", async () => {
  const workflow = await read(workflowPath);
  assert.match(workflow, /EXCLUDED_SOURCE_FILE_NAMES=MacMetalDisplayView\.mm/);
  assert.match(workflow, /MacMetalDisplayView\.mm was still compiled/);
  assert.match(workflow, /Metal frontend symbols remained in the OpenGL-only build/);
});

test("Catalina workflow inspects a simple-path copy of the executable", async () => {
  const workflow = await read(workflowPath);
  assert.match(workflow, /inspection_binary=\/tmp\/desmume-catalina-inspection-binary/);
  assert.match(workflow, /cp \"\$binary\" \"\$inspection_binary\"/);
  assert.match(workflow, /otool -L \"\$inspection_binary\"/);
  assert.match(workflow, /otool -l \"\$inspection_binary\"/);
  assert.doesNotMatch(workflow, /otool -L \"\$binary\"/);
});

test("Catalina launcher validates and directly execs the app binary", async () => {
  const workflow = await read(workflowPath);
  assert.match(workflow, /\$# -ne 2/);
  assert.match(workflow, /-r \"\$1\"/);
  assert.match(workflow, /1024/);
  assert.match(workflow, /65535/);
  assert.match(workflow, /CFBundleExecutable/);
  assert.match(workflow, /exec env RE_MCP_ARM9_GDB_PORT/);
  assert.doesNotMatch(workflow, /\bopen\s+-a\b/);
});

test("Catalina patch keeps the GDB startup boundary narrow", async () => {
  const patch = await read(patchPath);
  assert.match(patch, /RE_MCP_ARM9_GDB_PORT/);
  assert.match(patch, /1024/);
  assert.match(patch, /65535/);
  assert.match(patch, /toggleGDBStubActivate/);
  assert.doesNotMatch(patch, /system\(/);
  assert.doesNotMatch(patch, /subprocess/);
});
