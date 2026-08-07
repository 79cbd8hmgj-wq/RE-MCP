import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";

import type { ServerConfig } from "../src/config.js";
import { NdsError } from "../src/services/nds/errors.js";
import {
  ghidraInspectionRequestPath,
  ghidraInspectionResultPath,
} from "../src/services/nds/ghidra-inspection-model.js";
import {
  buildGhidraInspectionInvocation,
  resolveReMcpGhidraScriptPath,
  runGhidraInvocation,
  type GhidraInvocation,
  type ValidatedGhidraInstallation,
} from "../src/services/nds/ghidra-runner.js";
import type { NdsRomMap } from "../src/services/nds/rom-map.js";

const SHA = "1".repeat(64);
const PREFIX = SHA.slice(0, 16);
const REQUEST_ID = "0123456789abcdef";

const installation: ValidatedGhidraInstallation = {
  home: "/opt/ghidra_12.1.2_PUBLIC",
  analyzeHeadless: "/opt/ghidra_12.1.2_PUBLIC/support/analyzeHeadless",
  version: "12.1.2",
};

function map(): NdsRomMap {
  return {
    romPath: "/workspace/game.nds",
    fileSize: 0x10000,
    sha256: SHA,
    sha256Prefix: PREFIX,
    header: {
      gameTitle: "INSPECT",
      gameCode: "INSP",
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

function inspectionInvocation(processor: "arm9" | "arm7") {
  const sourceMap = map();
  const requestPath = ghidraInspectionRequestPath(sourceMap, "/workspace", REQUEST_ID);
  const resultPath = ghidraInspectionResultPath(sourceMap, "/workspace", REQUEST_ID);
  const invocation = buildGhidraInspectionInvocation({
    installation,
    map: sourceMap,
    processor,
    workspaceRoot: "/workspace",
    requestPath,
    resultPath,
  });
  return { invocation, requestPath, resultPath };
}

test("Ghidra inspection invocation is process-only read-only and disables auto-analysis", () => {
  const { invocation, requestPath, resultPath } = inspectionInvocation("arm9");
  assert.equal(invocation.executable, installation.analyzeHeadless);
  assert.equal(invocation.stage, "arm9-inspect");
  assert.deepEqual(invocation.args.slice(0, 2), [
    `/workspace/analysis/ghidra/nds/${SHA}/project`,
    `RE-MCP-${SHA}`,
  ]);
  assert.equal(hasSequence(invocation.args, ["-process", "RE-MCP_ARM9"]), true);
  assert.equal(invocation.args.includes("-readOnly"), true);
  assert.equal(invocation.args.includes("-noanalysis"), true);
  assert.equal(hasSequence(invocation.args, ["-scriptPath", resolveReMcpGhidraScriptPath()]), true);
  assert.equal(hasSequence(invocation.args, [
    "-postScript",
    "ReMcpInspectProgram.java",
    requestPath,
    resultPath,
  ]), true);
  for (const forbidden of [
    "-import",
    "-loader",
    "ReMcpPrepareProgram.java",
    "ReMcpImportEvidence.java",
    "ReMcpRecordAnalysis.java",
    "-overwrite",
  ]) {
    assert.equal(invocation.args.includes(forbidden), false, forbidden);
  }
  assert.equal(invocation.cwd, path.dirname(path.dirname(requestPath)));
});

test("Ghidra ARM7 inspection targets only the owned ARM7 program", () => {
  const { invocation } = inspectionInvocation("arm7");
  assert.equal(invocation.stage, "arm7-inspect");
  assert.equal(hasSequence(invocation.args, ["-process", "RE-MCP_ARM7"]), true);
  assert.equal(invocation.args.includes("RE-MCP_ARM9"), false);
});

test("Ghidra inspection invocation rejects request or result paths outside its generated root", () => {
  assert.throws(() => buildGhidraInspectionInvocation({
    installation,
    map: map(),
    processor: "arm9",
    workspaceRoot: "/workspace",
    requestPath: "/workspace/elsewhere/request.json",
    resultPath: "/workspace/elsewhere/result.json",
  }), /inspection|generated|path/i);
});

function directInvocation(
  source: string,
  stage: GhidraInvocation["stage"] = "arm9-inspect",
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

test("Ghidra inspection timeout maps to its dedicated category", async () => {
  await assert.rejects(
    runGhidraInvocation(
      directInvocation("setInterval(() => {}, 1000)"),
      config({ ghidraTimeoutMs: 100 }),
    ),
    (error: unknown) => errorCategory(error) === "ghidra-inspection-timeout",
  );
});

test("Ghidra inspection process failures and hidden script errors map to inspection failure", async () => {
  await assert.rejects(
    runGhidraInvocation(directInvocation("process.exit(9)"), config()),
    (error: unknown) => errorCategory(error) === "ghidra-inspection-failed",
  );
  await assert.rejects(
    runGhidraInvocation(
      directInvocation("process.stdout.write('REPORT SCRIPT ERROR: synthetic\\n')"),
      config(),
    ),
    (error: unknown) => errorCategory(error) === "ghidra-inspection-failed",
  );
});
