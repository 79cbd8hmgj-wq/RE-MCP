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
  throw new Error("Usage: node scripts/ghidra-inspection-hardening-acceptance.mjs <absolute-workspace-root> <relative-rom-path>");
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

if (!process.env.RE_MCP_GHIDRA_HOME) {
  throw new Error("RE_MCP_GHIDRA_HOME is required for real Ghidra inspection acceptance");
}
const config = {
  workspaceRoot,
  commandTimeoutMs: 120_000,
  maxOutputBytes: Number.parseInt(process.env.RE_MCP_MAX_OUTPUT_BYTES ?? "1000000", 10),
  ghidraHome: path.resolve(process.env.RE_MCP_GHIDRA_HOME),
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
assert.ok(before.length > 0, "expected populated Ghidra project before inspection");

const functionResult = await inspectNdsGhidraFunction(
  romPath,
  { processor: "arm9", runtimeAddress: 0x02000000 },
  config,
);
const functionDerived = derived(functionResult);
assert.equal(functionDerived.found, true);
assert.equal(functionResult.canonical.sourceRomSha256, map.sha256);
assert.equal(functionResult.canonical.component, "main");
assert.equal(typeof functionDerived.name, "string");
assert.ok(functionDerived.name.length > 0);
assert.ok(functionResult.reMcpEvidence && typeof functionResult.reMcpEvidence === "object");

const decompileResult = await decompileNdsGhidraFunction(
  romPath,
  { processor: "arm9", runtimeAddress: 0x02000000, maxCharacters: 20000 },
  config,
);
const decompileDerived = derived(decompileResult);
assert.equal(decompileDerived.found, true);
assert.equal(decompileDerived.completed, true, `decompiler failed: ${decompileDerived.error ?? "unknown"}`);
assert.equal(typeof decompileDerived.c, "string");
assert.ok(decompileDerived.c.length > 0);
assert.equal(decompileDerived.truncated, false);

const symbolResult = await searchNdsGhidraSymbols(
  romPath,
  { processor: "arm9", query: functionDerived.name, match: "exact", limit: 100, offset: 0 },
  config,
);
const symbols = derived(symbolResult).results;
assert.ok(symbols.some((entry) => entry.ghidraDerived?.name === functionDerived.name));
for (const entry of symbols) {
  assert.ok(entry.ghidraDerived && typeof entry.ghidraDerived === "object");
  assert.ok(entry.reMcpEvidence && typeof entry.reMcpEvidence === "object");
  assert.equal("name" in entry, false, "symbol authority fields must not be flattened");
}

const analystMarker = "REMCP_ACCEPTANCE_ANALYST_MARKER";
const markerResult = await searchNdsGhidraSymbols(
  romPath,
  { processor: "arm9", query: analystMarker, match: "exact", limit: 100, offset: 0 },
  config,
);
assert.ok(derived(markerResult).results.some((entry) => entry.ghidraDerived?.name === analystMarker));

// RE-MCP's proven main-to-overlay call is verified by the bootstrap acceptance
// through the owned call-evidence property map. The importer deliberately does
// not synthesize a Ghidra cross-address-space flow reference, so this harness
// only asserts Ghidra-native references that Ghidra itself is expected to derive.
const thumbReferencesResult = await listNdsGhidraReferences(
  romPath,
  { processor: "arm9", runtimeAddress: 0x02000004, direction: "from", limit: 100, offset: 0 },
  config,
);
const thumbReferences = derived(thumbReferencesResult).results;
const thumbCallReference = thumbReferences.find((reference) =>
  String(reference.ghidraDerived?.type).includes("CALL")
  && reference.ghidraDerived?.to?.offset === 0x02000010);
assert.ok(thumbCallReference, "expected Ghidra call reference from exact BLX call site to proven Thumb target");
assert.equal(thumbCallReference.canonical?.from?.component, "main");
assert.equal(thumbCallReference.canonical?.to?.component, "main");

const callsResult = await listNdsGhidraCalls(
  romPath,
  { processor: "arm9", runtimeAddress: 0x02000000, direction: "callees", limit: 100, offset: 0 },
  config,
);
const calls = derived(callsResult);
assert.equal(calls.found, true);
const thumbCallEdge = calls.edges.find((edge) => edge.ghidraDerived?.to?.offset === 0x02000010);
assert.ok(thumbCallEdge, "expected depth-one callee edge to Thumb target");
assert.equal(thumbCallEdge.canonical?.from?.component, "main");
assert.equal(thumbCallEdge.canonical?.to?.component, "main");
assert.ok(thumbCallEdge.reMcpEvidence && "directCall" in thumbCallEdge.reMcpEvidence);

for (const overlayId of [1, 2]) {
  const overlayResult = await inspectNdsGhidraFunction(
    romPath,
    { processor: "arm9", runtimeAddress: 0x02200000, overlayId },
    config,
  );
  assert.equal(overlayResult.canonical.component, "overlay");
  assert.equal(overlayResult.canonical.overlayId, overlayId);
  assert.equal(typeof overlayResult.ghidraDerived.found, "boolean");
}

const derivedFunctionResult = await inspectNdsGhidraFunction(
  romPath,
  { processor: "arm9", runtimeAddress: 0x02210000, overlayId: 3 },
  config,
);
assert.equal(derivedFunctionResult.canonical.component, "overlay");
assert.equal(derivedFunctionResult.canonical.overlayId, 3);
assert.equal(derivedFunctionResult.canonical.compressed, true);
assert.equal(derivedFunctionResult.canonical.fileBacked, false);
assert.equal(derivedFunctionResult.ghidraDerived.found, true);
assert.ok(derivedFunctionResult.reMcpEvidence && typeof derivedFunctionResult.reMcpEvidence === "object");

const derivedDecompileResult = await decompileNdsGhidraFunction(
  romPath,
  { processor: "arm9", runtimeAddress: 0x02210000, overlayId: 3, maxCharacters: 20000 },
  config,
);
assert.equal(derivedDecompileResult.canonical.compressed, true);
assert.equal(derivedDecompileResult.canonical.fileBacked, false);
assert.equal(derivedDecompileResult.ghidraDerived.found, true);
assert.equal(
  derivedDecompileResult.ghidraDerived.completed,
  true,
  `derived-overlay decompiler failed: ${derivedDecompileResult.ghidraDerived.error ?? "unknown"}`,
);
assert.equal(typeof derivedDecompileResult.ghidraDerived.c, "string");
assert.ok(derivedDecompileResult.ghidraDerived.c.length > 0);

const derivedReferencesResult = await listNdsGhidraReferences(
  romPath,
  {
    processor: "arm9",
    runtimeAddress: 0x02210000,
    overlayId: 3,
    direction: "from",
    limit: 100,
    offset: 0,
  },
  config,
);
const derivedReferences = derived(derivedReferencesResult).results;
const derivedInternalCall = derivedReferences.find((reference) =>
  String(reference.ghidraDerived?.type).includes("CALL")
  && reference.ghidraDerived?.from?.space === "RE_MCP_ARM9_OVL_3"
  && reference.ghidraDerived?.to?.space === "RE_MCP_ARM9_OVL_3"
  && reference.ghidraDerived?.to?.offset === 0x02210020);
assert.ok(derivedInternalCall, "expected Ghidra call reference within derived overlay 3");
assert.equal(derivedInternalCall.canonical?.from?.component, "overlay");
assert.equal(derivedInternalCall.canonical?.from?.overlayId, 3);
assert.equal(derivedInternalCall.canonical?.from?.compressed, true);
assert.equal(derivedInternalCall.canonical?.from?.fileBacked, false);
assert.equal(derivedInternalCall.canonical?.to?.component, "overlay");
assert.equal(derivedInternalCall.canonical?.to?.overlayId, 3);
assert.equal(derivedInternalCall.canonical?.to?.compressed, true);
assert.equal(derivedInternalCall.canonical?.to?.fileBacked, false);

const derivedCallsResult = await listNdsGhidraCalls(
  romPath,
  {
    processor: "arm9",
    runtimeAddress: 0x02210000,
    overlayId: 3,
    direction: "callees",
    limit: 100,
    offset: 0,
  },
  config,
);
const derivedCalls = derived(derivedCallsResult);
assert.equal(derivedCalls.found, true);
const derivedCallEdge = derivedCalls.edges.find((edge) =>
  edge.ghidraDerived?.from?.space === "RE_MCP_ARM9_OVL_3"
  && edge.ghidraDerived?.to?.space === "RE_MCP_ARM9_OVL_3"
  && edge.ghidraDerived?.to?.offset === 0x02210020);
assert.ok(derivedCallEdge, "expected depth-one derived-overlay callee edge");
assert.equal(derivedCallEdge.canonical?.from?.overlayId, 3);
assert.equal(derivedCallEdge.canonical?.to?.overlayId, 3);
assert.ok(derivedCallEdge.reMcpEvidence?.directCall,
  "derived-overlay call edge must preserve exact RE-MCP direct-call evidence");

const after = await snapshotProject(projectRoot);
assert.deepEqual(after, before, "read-only/no-analysis inspection changed persistent project bytes");

const markerAfter = await searchNdsGhidraSymbols(
  romPath,
  { processor: "arm9", query: analystMarker, match: "exact", limit: 100, offset: 0 },
  config,
);
assert.ok(derived(markerAfter).results.some((entry) => entry.ghidraDerived?.name === analystMarker));

process.stdout.write(JSON.stringify({
  ok: true,
  sourceRomSha256: map.sha256,
  functionName: functionDerived.name,
  decompilerCharacters: decompileDerived.c.length,
  derivedDecompilerCharacters: derivedDecompileResult.ghidraDerived.c.length,
  references: thumbReferences.length,
  calls: calls.edges.length,
  derivedReferences: derivedReferences.length,
  derivedCalls: derivedCalls.edges.length,
  projectFilesVerified: before.length,
  overlaysVerified: [1, 2, 3],
  derivedOverlayVerified: true,
  hardenedAuthorityShape: true,
}, null, 2) + "\n");
