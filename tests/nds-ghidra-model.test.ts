import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";

import type { DiscoverNdsFunctionsResult } from "../src/services/nds/function-discovery.js";
import type { ProvenFunctionIdentity } from "../src/services/nds/function-model.js";
import type { NdsOverlay } from "../src/services/nds/overlays.js";
import type { NdsRomMap } from "../src/services/nds/rom-map.js";
import {
  GHIDRA_ARM7_LANGUAGE,
  GHIDRA_ARM9_LANGUAGE,
  GHIDRA_BRIDGE_FORMAT,
  GHIDRA_BRIDGE_FORMAT_VERSION,
  buildGhidraBridgeManifest,
  ghidraGeneratedBridgeRoot,
  ghidraOverlaySpaceName,
  ghidraPersistentRoot,
  ghidraProgramName,
  ghidraProjectName,
  ghidraProjectRoot,
  ghidraStateRoot,
} from "../src/services/nds/ghidra-model.js";

function overlay(overrides: Partial<NdsOverlay>): NdsOverlay {
  return {
    processor: "arm9",
    overlayId: 1,
    ramAddress: 0x02200000,
    ramSize: 0x80,
    ramEnd: 0x02200080,
    bssSize: 0x20,
    bssEnd: 0x022000a0,
    staticInitStart: 0,
    staticInitEnd: 0,
    fileId: 0,
    romOffset: 0x3000,
    romSize: 0x80,
    compressedSize: 0,
    flags: 0,
    compressed: false,
    ...overrides,
  };
}

function mapWithSha(
  sha256: string,
  overlays: { arm9?: readonly NdsOverlay[]; arm7?: readonly NdsOverlay[] } = {},
): NdsRomMap {
  return {
    romPath: "/workspace/game.nds",
    fileSize: 0x10000,
    sha256,
    sha256Prefix: sha256.slice(0, 16),
    header: {
      gameTitle: "GHIDRA TEST",
      gameCode: "GHDR",
      makerCode: "01",
      unitCode: 0,
      deviceCapacity: 0,
      romVersion: 0,
      bannerOffset: 0,
      arm9: {
        romOffset: 0x4000,
        entryAddress: 0x02000000,
        ramAddress: 0x02000000,
        size: 0x100,
        romEnd: 0x4100,
        ramEnd: 0x02000100,
      },
      arm7: {
        romOffset: 0x5000,
        entryAddress: 0x02380000,
        ramAddress: 0x02380000,
        size: 0x80,
        romEnd: 0x5080,
        ramEnd: 0x02380080,
      },
      fnt: { offset: 0, size: 0, end: 0 },
      fat: { offset: 0, size: 0, end: 0 },
      arm9OverlayTable: { offset: 0, size: 0, end: 0 },
      arm7OverlayTable: { offset: 0, size: 0, end: 0 },
    },
    fat: [],
    filesystem: { directories: [], files: [] },
    overlays: {
      arm9: overlays.arm9 ?? [],
      arm7: overlays.arm7 ?? [],
    },
    executableRanges: [],
  };
}

function identity(
  processor: "arm9" | "arm7",
  runtimeAddress: number,
  mode: "arm" | "thumb" = "arm",
): ProvenFunctionIdentity {
  const base = processor === "arm9" ? 0x02000000 : 0x02380000;
  const romBase = processor === "arm9" ? 0x4000 : 0x5000;
  return {
    processor,
    component: "main",
    overlayId: null,
    runtimeAddress,
    romOffset: romBase + runtimeAddress - base,
    mode,
  };
}

function discovery(
  processor: "arm9" | "arm7",
  functions: DiscoverNdsFunctionsResult["functions"],
  calls: DiscoverNdsFunctionsResult["calls"] = [],
): DiscoverNdsFunctionsResult {
  return {
    status: "complete",
    processor,
    functions,
    calls,
    coverage: [{ component: "main", overlayId: null, status: "scanned" }],
    truncationReasons: [],
    totals: {
      functions: functions.length,
      callSites: calls.length,
      blocks: functions.length,
      instructions: functions.length,
      decodedBytes: functions.length * 4,
      traversalEdges: calls.length,
    },
  };
}

function discovered(
  entry: ProvenFunctionIdentity,
  evidence: DiscoverNdsFunctionsResult["functions"][number]["evidence"],
): DiscoverNdsFunctionsResult["functions"][number] {
  const owner = entry.component === "main" ? "main" : `overlay:${entry.overlayId}`;
  return {
    id: `${entry.processor}:${owner}:${entry.runtimeAddress.toString(16).padStart(8, "0")}:${entry.mode}`,
    entry,
    evidence,
    directCallerCount: evidence.filter((proof) => proof.kind === "direct-call").length,
    directCallSiteCount: evidence.filter((proof) => proof.kind === "direct-call").length,
    cfg: {
      status: "complete",
      truncationReasons: [],
      blocks: 1,
      instructions: 1,
      decodedBytes: entry.mode === "arm" ? 4 : 2,
      traversalEdges: 0,
      returnSites: 1,
      unresolvedEdges: 1,
    },
  };
}

test("Ghidra bridge model uses full SHA project isolation and exact deterministic names", () => {
  const shaA = "0123456789abcdef" + "0".repeat(48);
  const shaB = "0123456789abcdef" + "1".repeat(48);
  const mapA = mapWithSha(shaA);
  const mapB = mapWithSha(shaB);
  const workspace = "/workspace";

  assert.equal(GHIDRA_BRIDGE_FORMAT, "re-mcp-nds-ghidra");
  assert.equal(GHIDRA_BRIDGE_FORMAT_VERSION, 1);
  assert.equal(GHIDRA_ARM9_LANGUAGE, "ARM:LE:32:v5t");
  assert.equal(GHIDRA_ARM7_LANGUAGE, "ARM:LE:32:v4t");
  assert.equal(ghidraProjectName(mapA), `RE-MCP-${shaA}`);
  assert.equal(ghidraProgramName("arm9"), "RE-MCP_ARM9");
  assert.equal(ghidraProgramName("arm7"), "RE-MCP_ARM7");
  assert.equal(ghidraOverlaySpaceName("arm9", 7), "RE_MCP_ARM9_OVL_7");
  assert.equal(
    ghidraGeneratedBridgeRoot(mapA, workspace),
    path.join(workspace, "analysis", "generated", "nds", mapA.sha256Prefix, "ghidra-bridge"),
  );
  assert.equal(
    ghidraPersistentRoot(mapA, workspace),
    path.join(workspace, "analysis", "ghidra", "nds", shaA),
  );
  assert.equal(ghidraProjectRoot(mapA, workspace), path.join(ghidraPersistentRoot(mapA, workspace), "project"));
  assert.equal(ghidraStateRoot(mapA, workspace), path.join(ghidraPersistentRoot(mapA, workspace), "state"));
  assert.notEqual(ghidraPersistentRoot(mapA, workspace), ghidraPersistentRoot(mapB, workspace));
});

test("Ghidra bridge manifest preserves overlay backing semantics and compressed omission", () => {
  const map = mapWithSha("a".repeat(64), {
    arm9: [
      overlay({ overlayId: 9, fileId: 2, romOffset: 0x3200 }),
      overlay({ overlayId: 3, fileId: 1, romOffset: 0x3100, compressed: true, compressedSize: 0x60, flags: 1 }),
    ],
    arm7: [overlay({ processor: "arm7", overlayId: 4, ramAddress: 0x02390000, ramEnd: 0x02390080, bssEnd: 0x023900a0 })],
  });

  const manifest = buildGhidraBridgeManifest({
    map,
    arm9: discovery("arm9", []),
    arm7: discovery("arm7", []),
    artifacts: [],
  });

  assert.deepEqual(manifest.processors.map((entry) => [entry.processor, entry.language, entry.programName]), [
    ["arm9", "ARM:LE:32:v5t", "RE-MCP_ARM9"],
    ["arm7", "ARM:LE:32:v4t", "RE-MCP_ARM7"],
  ]);

  const arm9 = manifest.processors[0]!;
  assert.deepEqual(arm9.overlays.map((entry) => entry.overlayId), [3, 9]);
  assert.deepEqual(arm9.overlays.map((entry) => entry.importStatus), ["not-imported-compressed", "importable"]);
  assert.equal(arm9.overlays[0]!.fileBackedSize, 0x80);
  assert.equal(arm9.overlays[0]!.bssSize, 0x20);
  assert.equal(arm9.overlays[0]!.artifactPath, "../overlays/arm9/overlay_3.bin");
  assert.equal(arm9.main.artifactPath, "imports/RE-MCP_ARM9");
  assert.deepEqual(manifest.generatedResultPaths, {
    arm9: "results/arm9.json",
    arm7: "results/arm7.json",
  });
});

test("Ghidra bridge manifest canonicalizes proven entry proofs and calls without inventing body boundaries", () => {
  const map = mapWithSha("b".repeat(64));
  const entry = identity("arm9", 0x02000000, "arm");
  const callee = identity("arm9", 0x02000010, "thumb");
  const directProof = {
    kind: "direct-call" as const,
    caller: {
      functionId: "arm9:main:02000000:arm",
      component: "main" as const,
      overlayId: null,
      instructionAddress: 0x02000004,
      instructionRomOffset: 0x4004,
      mode: "arm" as const,
    },
    target: callee,
  };
  const programEntryProof = {
    kind: "program-entry" as const,
    processor: "arm9" as const,
    headerEntryAddress: 0x02000000,
  };
  const arm9 = discovery(
    "arm9",
    [
      discovered(callee, [directProof]),
      discovered(entry, [programEntryProof]),
    ],
    [
      {
        callerFunctionId: "arm9:main:02000000:arm",
        instructionAddress: 0x02000004,
        instructionRomOffset: 0x4004,
        calleeFunctionId: "arm9:main:02000010:thumb",
      },
    ],
  );

  const manifest = buildGhidraBridgeManifest({
    map,
    arm9,
    arm7: discovery("arm7", []),
    artifacts: [{ path: "scripts/ReMcpPrepareProgram.java", sha256: "c".repeat(64), size: 123 }],
  });

  assert.deepEqual(manifest.discovery[0]!.functions.map((fn) => fn.id), [
    "arm9:main:02000000:arm",
    "arm9:main:02000010:thumb",
  ]);
  assert.deepEqual(manifest.discovery[0]!.functions[0]!.evidence.map((proof) => proof.kind), ["program-entry"]);
  assert.deepEqual(manifest.discovery[0]!.functions[1]!.evidence.map((proof) => proof.kind), ["direct-call"]);
  assert.deepEqual(manifest.discovery[0]!.calls.map((call) => call.calleeFunctionId), ["arm9:main:02000010:thumb"]);

  const serialized = JSON.stringify(manifest);
  assert.equal(serialized.includes("functionEnd"), false);
  assert.equal(serialized.includes("bodyEnd"), false);
  assert.equal(serialized.includes("bodySize"), false);
  assert.deepEqual(manifest.artifacts.map((artifact) => artifact.path), ["scripts/ReMcpPrepareProgram.java"]);
});
