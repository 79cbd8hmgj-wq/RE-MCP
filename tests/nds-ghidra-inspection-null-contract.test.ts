import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import test from "node:test";

const scriptPath = fileURLToPath(new URL("../resources/ghidra/ReMcpInspectProgram.java", import.meta.url));

test("Ghidra inspection serializes null-valued authority fields instead of omitting them", async () => {
  const source = await readFile(scriptPath, "utf8");
  assert.match(
    source,
    /new GsonBuilder\(\)\.serializeNulls\(\)\.disableHtmlEscaping\(\)\.create\(\)/,
    "inspection result schemas require explicit JSON nulls for absent RE-MCP evidence and optional Ghidra fields",
  );
  assert.match(source, /addNullable\s*\(\s*evidence\s*,\s*"overlayId"/);
  assert.match(source, /JsonNull\.INSTANCE/);
});
