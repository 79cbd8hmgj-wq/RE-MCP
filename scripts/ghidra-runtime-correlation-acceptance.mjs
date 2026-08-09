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
  throw new Error(
    "Usage: node scripts/ghidra-runtime-correlation-acceptance.mjs <absolute-workspace-root> <relative-rom-path>",
  );
}
const romPath = path.resolve(workspaceRoot, romRelative);
if (!romPath.startsWith(`${workspaceRoot}${path.sep}`)) {
  throw new Error("ROM path escapes the acceptance workspace");
}

function compiledRoot() {
  const sourceBuild = path.resolve("dist", "src");
  const packagedBuild = path.resolve("dist");
  if (existsSync(path.join(sourceBuild, "services", "nds", "runtime-correlation.js"))) {
    return sourceBuild;
  }
  if (existsSync(path.join(packagedBuild, "services", "nds", "runtime-correlation.js"))) {
    return packagedBuild;
  }
  throw new Error("Build RE-MCP before running the Ghidra runtime-correlation acceptance harness");
}

const dist = compiledRoot();
async function importBuilt(relative) {
  return await import(pathToFileURL(path.join(dist, relative)).href);
}

const { createCapstoneArmBackend } = await importBuilt("services/disassembly/capstone.js");
const { ghidraProjectRoot } = await importBuilt("services/nds/ghidra-model.js");
const { readNdsRomMap } = await importBuilt("services/nds/rom-map.js");
const { createRuntimeGhidraEnricher } = await importBuilt(
  "services/nds/runtime-correlation-ghidra.js",
);
const { correlateNdsStopContext } = await importBuilt("services/nds/runtime-correlation.js");

if (!process.env.RE_MCP_GHIDRA_HOME) {
  throw new Error("RE_MCP_GHIDRA_HOME is required for real Ghidra runtime correlation acceptance");
}
const config = {
  workspaceRoot,
  commandTimeoutMs: 120_000,
  maxOutputBytes: Number.parseInt(process.env.RE_MCP_MAX_OUTPUT_BYTES ?? "1000000", 10),
  ghidraHome: path.resolve(process.env.RE_MCP_GHIDRA_HOME),
  ghidraTimeoutMs: Number.parseInt(process.env.RE_MCP_GHIDRA_TIMEOUT_MS ?? "900000", 10),
};

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

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
        sha256: sha256(bytes),
      });
    }
  }
  await walk(root);
  rows.sort((left, right) => left.path.localeCompare(right.path));
  return rows;
}

function stopContext(pc) {
  return {
    capturedAt: "2026-08-09T15:00:00.000Z",
    stop: { kind: "signal", signal: 5, fields: {}, raw: "S05" },
    registers: {
      r0: 0,
      r1: 1,
      r2: 2,
      r3: 3,
      r4: 4,
      r5: 5,
      r6: 6,
      r7: 7,
      r8: 8,
      r9: 9,
      r10: 10,
      r11: 11,
      r12: 12,
      sp: 0x023ff000,
      lr: 0x02000010,
      pc,
      cpsr: 0x60000013,
      mode: "arm",
      byteOrder: "little",
      raw: "00".repeat(168),
    },
    pcWindow: { address: pc, length: 4, dataHex: "00000000" },
    stackWindow: { address: 0x023ff000, length: 4, dataHex: "00000000" },
    additionalRegions: [],
  };
}

function requireAvailableGhidra(candidate, label) {
  const ghidraDerived = candidate.ghidraDerived;
  assert.equal(
    ghidraDerived.status,
    "available",
    `${label} Ghidra enrichment was not available: ${JSON.stringify(ghidraDerived)}`,
  );
  assert.equal(ghidraDerived.function.ghidraDerived.found, true, `${label} function not found`);
  assert.ok(ghidraDerived.decompilation, `${label} decompilation was not returned`);
  assert.equal(
    ghidraDerived.decompilation.ghidraDerived.found,
    true,
    `${label} decompiled function was not found`,
  );
  assert.equal(
    ghidraDerived.decompilation.ghidraDerived.completed,
    true,
    `${label} decompilation did not complete`,
  );
  return ghidraDerived;
}

const map = await readNdsRomMap(romPath);
const projectRoot = ghidraProjectRoot(map, workspaceRoot);
const projectBefore = await snapshotProject(projectRoot);
assert.ok(projectBefore.length > 0, "expected populated Ghidra project before runtime correlation");
const romBefore = await readFile(romPath);
const romShaBefore = sha256(romBefore);
assert.equal(romShaBefore, map.sha256);

const ghidraEnricher = createRuntimeGhidraEnricher(config);
const backend = await createCapstoneArmBackend();
let mainResult;
let compressedResult;
try {
  mainResult = await correlateNdsStopContext(
    {
      romPath,
      romDisplayPath: romRelative,
      expectedRomSha256: map.sha256,
      stopContext: stopContext(0x02000000),
      options: {
        nearbyInstructions: 8,
        referenceLimit: 16,
        maxOutputBytes: config.maxOutputBytes,
        includeGhidra: true,
        decompileGhidraFunction: true,
      },
    },
    backend,
    ghidraEnricher,
  );

  compressedResult = await correlateNdsStopContext(
    {
      romPath,
      romDisplayPath: romRelative,
      expectedRomSha256: map.sha256,
      stopContext: stopContext(0x02210000),
      options: {
        nearbyInstructions: 8,
        referenceLimit: 16,
        maxOutputBytes: config.maxOutputBytes,
        includeGhidra: true,
        decompileGhidraFunction: true,
      },
    },
    backend,
    ghidraEnricher,
  );
} finally {
  backend.close();
}

assert.equal(mainResult.runtimeObserved.pc, 0x02000000);
assert.equal(mainResult.runtimeObserved.mode, "arm");
assert.equal(mainResult.rom.sha256, map.sha256);
assert.equal(mainResult.rom.identityMatched, true);
assert.equal(mainResult.canonical.status, "resolved");
assert.equal(mainResult.candidates.length, 1);
const mainCandidate = mainResult.candidates[0];
assert.ok(mainCandidate);
assert.equal(mainCandidate.canonical.kind, "arm9-main");
assert.equal(mainCandidate.canonical.overlayId, null);
assert.equal(mainCandidate.static.status, "available");
const mainGhidra = requireAvailableGhidra(mainCandidate, "main");

assert.equal(compressedResult.runtimeObserved.pc, 0x02210000);
assert.equal(compressedResult.runtimeObserved.mode, "arm");
assert.equal(compressedResult.rom.sha256, map.sha256);
assert.equal(compressedResult.canonical.status, "resolved");
assert.equal(compressedResult.candidates.length, 1);
const compressedCandidate = compressedResult.candidates[0];
assert.ok(compressedCandidate);
assert.equal(compressedCandidate.canonical.kind, "arm9-overlay");
assert.equal(compressedCandidate.canonical.overlayId, 3, "expected compressed overlay 3");
assert.equal(compressedCandidate.canonical.compressed, true);
assert.equal(compressedCandidate.canonical.representation, "derived-overlay");
assert.equal(compressedCandidate.canonical.romOffset, null);
assert.equal(compressedCandidate.static.status, "available");
const compressedGhidra = requireAvailableGhidra(compressedCandidate, "compressed overlay 3");
assert.equal("loadedOverlay" in compressedResult.canonical, false);
assert.equal("bestMatch" in compressedResult.canonical, false);

const romAfter = await readFile(romPath);
if (sha256(romAfter) !== romShaBefore) {
  throw new Error("source ROM changed during runtime correlation acceptance");
}
const projectAfter = await snapshotProject(projectRoot);
assert.deepEqual(
  projectAfter,
  projectBefore,
  "read-only runtime correlation changed persistent project bytes",
);

process.stdout.write(JSON.stringify({
  ok: true,
  sourceRomSha256: map.sha256,
  mainRuntimeAddress: 0x02000000,
  mainGhidraFound: mainGhidra.function.ghidraDerived.found,
  compressedOverlayRuntimeAddress: 0x02210000,
  compressedOverlayId: 3,
  compressedOverlayRepresentation: compressedCandidate.canonical.representation,
  compressedOverlayRomOffset: compressedCandidate.canonical.romOffset,
  compressedOverlayGhidraFound: compressedGhidra.function.ghidraDerived.found,
  projectFilesVerified: projectBefore.length,
  readOnlyVerified: true,
  authoritySeparated: true,
}, null, 2) + "\n");
