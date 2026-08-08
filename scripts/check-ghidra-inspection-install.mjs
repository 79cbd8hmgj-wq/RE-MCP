import { access, readFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";

const root = path.resolve(process.argv[2] ?? process.cwd());

for (const relative of [
  "dist/services/nds/ghidra-inspection.js",
  "dist/services/nds/ghidra-inspection-readiness.js",
  "dist/tools/nds-ghidra.js",
  "resources/ghidra/ReMcpInspectProgram.java",
]) {
  await access(path.join(root, relative));
}

const builtIndex = await readFile(path.join(root, "dist/index.js"), "utf8");
for (const tool of [
  "nds_ghidra_inspect_function",
  "nds_ghidra_decompile_function",
  "nds_ghidra_search_symbols",
  "nds_ghidra_list_references",
  "nds_ghidra_list_calls",
]) {
  if (!builtIndex.includes(tool)) {
    throw new Error(`Packaged server does not advertise controlled Ghidra inspection tool: ${tool}`);
  }
}

const resource = await readFile(
  path.join(root, "resources", "ghidra", "ReMcpInspectProgram.java"),
  "utf8",
);
if (!resource.includes("@category RE-MCP")) {
  throw new Error("Packaged Ghidra inspection resource lacks RE-MCP script identity");
}
for (const required of ["inspect-function", "decompile-function", "search-symbols", "list-references", "list-calls"]) {
  if (!resource.includes(required)) {
    throw new Error(`Packaged Ghidra inspection resource lacks operation: ${required}`);
  }
}

process.stdout.write(JSON.stringify({ ok: true, ghidraInspection: true, root }, null, 2) + "\n");
