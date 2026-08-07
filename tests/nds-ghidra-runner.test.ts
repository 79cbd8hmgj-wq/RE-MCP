import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";

import type { ServerConfig } from "../src/config.js";
import { NdsError } from "../src/services/nds/errors.js";
import type { GeneratedGhidraBridge } from "../src/services/nds/ghidra-bridge.js";
import type { GhidraBridgeManifest } from "../src/services/nds/ghidra-model.js";
import {
  buildGhidraImportInvocation,
  buildGhidraProcessInvocation,
  resolveReMcpGhidraScriptPath,
  runGhidraInvocation,
  type GhidraInvocation,
  type ValidatedGhidraInstallation,
} from "../src/services/nds/ghidra-runner.js";
import type { NdsRomMap } from "../src/services/nds/rom-map.js";

const SHA = "1".repeat(64);
const PREFIX = SHA.slice(0, 16);

function map(): NdsRomMap {
  return {
    romPath: "/workspace/game.nds",
    fileSize: 0x10000,
    sha256: SHA,
    sha256Prefix: PREFIX,
    header: {
      gameTitle: "GHIDRA",
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
        entryAddress: 0x03800000,
        ramAddress: 0x03800000,
        size: 0x80,
        romEnd: 0x5080,
        ramEnd: 0x03800080,
      },
      fnt: { offset: 0, size: 0, end: 0 },
      fat: { offset: 0, size: 0, end: 0 },
      arm9OverlayTable: { offset: 0, size: 0, end: 0 },
      arm7OverlayTable: { offset: 0, size: 0, end: 0 },
    },
    fat: [],
    filesystem: { directories: [], files: [] },
    overlays: { arm9: [], arm7: [] },
    executableRanges: [],
  };
}

function manifest(): GhidraBridgeManifest {
  return {
    format: "re-mcp-nds-ghidra",
    formatVersion: 1,
    sourceRomSha256: SHA,
    sha256Prefix: PREFIX,
    processors: [
      {
        processor: "arm9",
        language: "ARM:LE:32:v5t",
        programName: "RE-MCP_ARM9",
        main: {
          artifactPath: "../arm9.bin",
          romOffset: 0x4000,
          runtimeAddress: 0x02000000,
          entryAddress: 0x02000000,
          fileBackedSize: 0x100,
        },
        overlays: [],
      },
      {
        processor: "arm7",
        language: "ARM:LE:32:v4t",
        programName: "RE-MCP_ARM7",
        main: {
          artifactPath: "../arm7.bin",
          romOffset: 0x5000,
          runtimeAddress: 0x03800000,
          entryAddress: 0x03800000,
          fileBackedSize: 0x80,
        },
        overlays: [],
      },
    ],
    discovery: [
      {
        processor: "arm9",
        status: "complete",
        functions: [],
        calls: [],
        coverage: [],
        truncationReasons: [],
        totals: { functions: 0, callSites: 0, blocks: 0, instructions: 0, decodedBytes: 0, traversalEdges: 0 },
      },
      {
        processor: "arm7",
        status: "complete",
        functions: [],
        calls: [],
        coverage: [],
        truncationReasons: [],
        totals: { functions: 0, callSites: 0, blocks: 0, instructions: 0, decodedBytes: 0, traversalEdges: 0 },
      },
    ],
    artifacts: [],
    generatedResultPaths: { arm9: "results/arm9.json", arm7: "results/arm7.json" },
  };
}

function bridge(): GeneratedGhidraBridge {
  const bridgeRoot = `/workspace/analysis/generated/nds/${PREFIX}/ghidra-bridge`;
  return {
    bridgeRoot,
    manifestPath: path.join(bridgeRoot, "manifest.json"),
    manifestSha256: "2".repeat(64),
    manifest: manifest(),
  };
}

const installation: ValidatedGhidraInstallation = {
  home: "/opt/ghidra_12.1.2_PUBLIC",
  analyzeHeadless: "/opt/ghidra_12.1.2_PUBLIC/support/analyzeHeadless",
  version: "12.1.2",
};

function config(overrides: Partial<ServerConfig> = {}): ServerConfig {
  return {
    workspaceRoot: "/workspace",
    commandTimeoutMs: 30_000,
    maxOutputBytes: 64 * 1024,
    ghidraHome: installation.home,
    ghidraTimeoutMs: 900_000,
    ...overrides,
  };
}

function hasSequence(args: readonly string[], sequence: readonly string[]): boolean {
  for (let start = 0; start <= args.length - sequence.length; start += 1) {
    if (sequence.every((value, index) => args[start + index] === value)) return true;
  }
  return false;
}

test("Ghidra import invocation uses exact canonical ARM9 BinaryLoader and RE-MCP scripts", () => {
  const invocation = buildGhidraImportInvocation({
    installation,
    map: map(),
    bridge: bridge(),
    processor: "arm9",
    workspaceRoot: "/workspace",
  });
  const scriptPath = resolveReMcpGhidraScriptPath();

  assert.equal(invocation.executable, installation.analyzeHeadless);
  assert.equal(invocation.stage, "arm9-import");
  assert.deepEqual(invocation.args.slice(0, 2), [
    `/workspace/analysis/ghidra/nds/${SHA}/project`,
    `RE-MCP-${SHA}`,
  ]);
  assert.equal(hasSequence(invocation.args, ["-import", `/workspace/analysis/generated/nds/${PREFIX}/arm9.bin`]), true);
  assert.equal(hasSequence(invocation.args, ["-loader", "BinaryLoader"]), true);
  assert.equal(hasSequence(invocation.args, ["-processor", "ARM:LE:32:v5t"]), true);
  assert.equal(hasSequence(invocation.args, ["-loader-baseAddr", "0x2000000"]), true);
  assert.equal(hasSequence(invocation.args, ["-scriptPath", scriptPath]), true);
  assert.equal(hasSequence(invocation.args, ["-preScript", "ReMcpPrepareProgram.java", bridge().manifestPath, "arm9"]), true);
  assert.equal(hasSequence(invocation.args, ["-preScript", "ReMcpImportEvidence.java", bridge().manifestPath, "arm9"]), true);
  assert.equal(
    hasSequence(invocation.args, [
      "-postScript",
      "ReMcpRecordAnalysis.java",
      bridge().manifestPath,
      "arm9",
      path.join(bridge().bridgeRoot, "results", "arm9.json"),
    ]),
    true,
  );
  assert.equal(invocation.args.includes("-overwrite"), false);
});

test("Ghidra ARM7 import uses the exact v4t language and canonical base", () => {
  const invocation = buildGhidraImportInvocation({
    installation,
    map: map(),
    bridge: bridge(),
    processor: "arm7",
    workspaceRoot: "/workspace",
  });
  assert.equal(hasSequence(invocation.args, ["-processor", "ARM:LE:32:v4t"]), true);
  assert.equal(hasSequence(invocation.args, ["-loader-baseAddr", "0x3800000"]), true);
});

test("Ghidra reconciliation invocation processes the owned program without import or overwrite", () => {
  const invocation = buildGhidraProcessInvocation({
    installation,
    map: map(),
    bridge: bridge(),
    processor: "arm9",
    workspaceRoot: "/workspace",
  });
  assert.equal(invocation.stage, "arm9-process");
  assert.equal(hasSequence(invocation.args, ["-process", "RE-MCP_ARM9"]), true);
  assert.equal(invocation.args.includes("-import"), false);
  assert.equal(invocation.args.includes("-loader"), false);
  assert.equal(invocation.args.includes("-overwrite"), false);
});

test("RE-MCP Ghidra script path resolves to the packaged/source resources directory", () => {
  const scriptPath = resolveReMcpGhidraScriptPath();
  assert.equal(path.basename(scriptPath), "ghidra");
  assert.equal(path.basename(path.dirname(scriptPath)), "resources");
});

function directInvocation(
  source: string,
  stage: GhidraInvocation["stage"] = "arm9-process",
): GhidraInvocation {
  return {
    executable: process.execPath,
    args: ["-e", source],
    cwd: process.cwd(),
    stage,
  };
}

function errorCategory(error: unknown): string | null {
  return error instanceof NdsError ? String(error.category) : null;
}

test("Ghidra runner maps process timeout to a structured category", async () => {
  await assert.rejects(
    runGhidraInvocation(
      directInvocation("setInterval(() => {}, 1000)"),
      config({ ghidraTimeoutMs: 100 }),
    ),
    (error: unknown) => errorCategory(error) === "ghidra-analysis-timeout",
  );
});

test("Ghidra runner terminates output overflow and reports the output category", async () => {
  await assert.rejects(
    runGhidraInvocation(
      directInvocation("process.stdout.write('x'.repeat(1024)); setInterval(() => {}, 1000)"),
      config({ ghidraTimeoutMs: 5_000, maxOutputBytes: 64 }),
    ),
    (error: unknown) => errorCategory(error) === "ghidra-output-limit",
  );
});

test("Ghidra runner maps nonzero import and process exits by stage", async () => {
  await assert.rejects(
    runGhidraInvocation(directInvocation("process.exit(3)", "arm9-import"), config()),
    (error: unknown) => errorCategory(error) === "ghidra-import-failed",
  );
  await assert.rejects(
    runGhidraInvocation(directInvocation("process.exit(4)", "arm9-process"), config()),
    (error: unknown) => errorCategory(error) === "ghidra-analysis-failed",
  );
});

test("Ghidra runner preserves a bounded failure diagnostic", async () => {
  const marker = "GHIDRA_DIAGNOSTIC_MARKER";
  await assert.rejects(
    runGhidraInvocation(
      directInvocation(`console.error('${marker}'); process.exit(5)`, "arm9-import"),
      config(),
    ),
    (error: unknown) =>
      error instanceof NdsError &&
      error.category === "ghidra-import-failed" &&
      error.message.includes(marker) &&
      error.message.length < 8_192,
  );
});

test("Ghidra runner identifies a project lock without destructive recovery", async () => {
  await assert.rejects(
    runGhidraInvocation(
      directInvocation("console.error('LockException: unable to obtain write-lock on project'); process.exit(1)"),
      config(),
    ),
    (error: unknown) => errorCategory(error) === "ghidra-project-locked",
  );
});
