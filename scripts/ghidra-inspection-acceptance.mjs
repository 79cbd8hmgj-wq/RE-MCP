import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { pathToFileURL } from "node:url";

const workspaceRoot = path.resolve(process.argv[2] ?? "");
const romRelative = process.argv[3] ?? "";
if (!path.isAbsolute(workspaceRoot) || romRelative.length === 0 || path.isAbsolute(romRelative)) {
  throw new Error("Usage: node scripts/ghidra-inspection-acceptance.mjs <absolute-workspace-root> <relative-rom-path>");
}
const romPath = path.resolve(workspaceRoot, romRelative);
if (!romPath.startsWith(`${workspaceRoot}${path.sep}`)) {
  throw new Error("ROM path escapes the acceptance workspace");
}

function compiledRoot() {
  const sourceBuild = path.resolve("dist", "src");
  const packagedBuild = path.resolve("dist");
  if (existsSync(path.join(sourceBuild, "services", "nds", "ghidra-inspection.js"))) return sourceBuild;
  if (existsSync(path.join(packagedBuild, "services", "nds", "ghidra-inspection.js"))) return packagedBuild;
  throw new Error("Build RE-MCP before running the Ghidra inspection acceptance harness");
}

const dist = compiledRoot();
async function importBuilt(relative) {
  return await import(pathToFileURL(path.join(dist, relative)).href);
}

const {
  inspectNdsGhidraFunction,
  decompileNdsGhidraFunction,
  searchNdsGhidraSymbols,
  listNdsGhidraReferences,
  listNdsGhidraCalls,
} = await importBuilt("services/nds/ghidra-inspection.js");
const { readNdsRomMap } = await importBuilt("services/nds/rom-map.js");
const { ghidraProjectRoot } = await importBuilt("services/nds/ghidra-model.js");

const ghidraHome = path.resolve(process.env.RE_MCP_GHIDRA_HOME ?? "");
if (!process.env.RE_MCP_GHIDRA_HOME) {
  throw new Error("RE_MCP_GHIDRA_HOME is required for real Ghidra inspection acceptance");
}
const config = {
  workspaceRoot,
  commandTimeoutMs: 120_000,
  maxOutputBytes: Number.parseInt(process.env.RE_MCP_MAX_OUTPUT_BYTES ?? "1000000", 10),
  ghidraHome,
  ghidraTimeoutMs: Number.parseInt(process.env.RE_MCP_GHIDRA_TIMEOUT_MS ?? "900000", 10),
};

const TRANSIENT_PROJECT_NAMES = new Set(["project.lock", ".lock"]);

async function snapshotProject(root) {
  const rows = [];
  async function walk(directory) {
    const entries = await readdir(directory, { withFileTypes: true });
    entries.sort((left, right) => left.name.localeCompare(right.name));
    for (const entry of entries) {
      if (TRANSIENT_PROJECT_NAMES.has(entry.name)) continue;
      const absolute = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        await walk(absolute);
        continue;
      }
      if (!entry.isFile()) continue;
      const bytes = await readFile(absolute);
      rows.push({
        path: path.relative(root, absolute),
        size: bytes.length,
        sha256: createHash("sha256").update(bytes).digest("hex"),
      });
    }
  }
  await walk(root);
  rows.sort((left, right) => left.path.localeCompare(right.path));
  return rows;
}

function derived(result) {
  assert.ok(result && typeof result === "object");
  assert.ok(result.ghidraDerived && typeof result.ghidraDerived === "object");
  return result.ghidraDerived;
}

const map = await readNdsRomMap(romPath);
const projectRoot = ghidraProjectRoot(map, workspaceRoot);
const before = await snapshotProject(projectRoot);
assert.ok(before.length > 0, "expected a populated persistent Ghidra project before inspection");

const functionResult = await inspectNdsGhidraFunction(
  romPath,
  { processor: "arm9", runtimeAddress: 0x02000000 },
  config,
);
const functionDerived = derived(functionResult);
assert.equal(functionDerived.found, true, "expected Ghidra function at ARM9 program entry");
assert.equal(typeof functionDerived.name, "string");
assert.ok(functionDerived.name.length > 0);
assert.equal(functionResult.canonical.sourceRomSha256, map.sha256);
assert.equal(functionResult.canonical.component, "main");

const decompileResult = await decompileNdsGhidraFunction(
  romPath,
  { processor: "arm9", runtimeAddress: 0x02000000, maxCharacters: 20000 },
  config,
);
const decompileDerived = derived(decompileResult);
assert.equal(decompileDerived.found, true);
assert.equal(decompileDerived.completed, true, `decompiler failed: ${decompileDerived.error ?? "unknown"}`);
assert.equal(typeof decompileDerived.c, "string");
assert.ok(decompileDerived.c.length > 0, "expected non-empty decompiler output");
assert.equal(decompileDerived.truncated, false);

const symbolResult = await searchNdsGhidraSymbols(
  romPath,
  {
    processor: "arm9",
    query: functionDerived.name,
    match: "exact",
    limit: 100,
    offset: 0,
  },
  config,
);
const symbolDerived = derived(symbolResult);
assert.ok(
  symbolDerived.results.some((entry) => entry.name === functionDerived.name),
  "expected exact function symbol search to find the inspected function",
);

const analystMarker = "REMCP_ACCEPTANCE_ANALYST_MARKER";
const markerResult = await searchNdsGhidraSymbols(
  romPath,
  { processor: "arm9", query: analystMarker, match: "exact", limit: 100, offset: 0 },
  config,
);
assert.ok(
  derived(markerResult).results.some((entry) => entry.name === analystMarker),
  "expected analyst marker created by bootstrap acceptance to remain present",
);

const referencesResult = await listNdsGhidraReferences(
  romPath,
  {
    processor: "arm9",
    runtimeAddress: 0x02000000,
    direction: "from",
    limit: 100,
    offset: 0,
  },
  config,
);
const references = derived(referencesResult).results;
assert.ok(
  references.some((reference) =>
    String(reference.type).includes("CALL")
    && reference.to?.offset === 0x02000008),
  "expected Ghidra call reference from ARM9 entry to the proven Thumb target",
);

const callsResult = await listNdsGhidraCalls(
  romPath,
  {
    processor: "arm9",
    runtimeAddress: 0x02000000,
    direction: "callees",
    limit: 100,
    offset: 0,
  },
  config,
);
const calls = derived(callsResult);
assert.equal(calls.found, true);
assert.ok(
  calls.edges.some((edge) => edge.to?.offset === 0x02000008),
  "expected depth-one callee edge to the Thumb target",
);

for (const overlayId of [1, 2]) {
  const overlayResult = await inspectNdsGhidraFunction(
    romPath,
    { processor: "arm9", runtimeAddress: 0x02200000, overlayId },
    config,
  );
  assert.equal(overlayResult.canonical.component, "overlay");
  assert.equal(overlayResult.canonical.overlayId, overlayId);
  assert.ok(
    overlayResult.ghidraDerived && typeof overlayResult.ghidraDerived.found === "boolean",
    `expected overlay ${overlayId} inspection to resolve its distinct Ghidra overlay address space`,
  );
}

const after = await snapshotProject(projectRoot);
assert.deepEqual(
  after,
  before,
  "read-only/no-analysis inspection changed persistent non-transient Ghidra project bytes",
);

const markerAfter = await searchNdsGhidraSymbols(
  romPath,
  { processor: "arm9", query: analystMarker, match: "exact", limit: 100, offset: 0 },
  config,
);
assert.ok(
  derived(markerAfter).results.some((entry) => entry.name === analystMarker),
  "analyst marker disappeared after read-only inspection",
);

process.stdout.write(JSON.stringify({
  ok: true,
  sourceRomSha256: map.sha256,
  functionName: functionDerived.name,
  decompilerCharacters: decompileDerived.c.length,
  references: references.length,
  calls: calls.edges.length,
  projectFilesVerified: before.length,
  overlaysVerified: [1, 2],
}, null, 2) + "\n");
