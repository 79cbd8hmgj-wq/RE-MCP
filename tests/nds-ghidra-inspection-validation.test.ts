import assert from "node:assert/strict";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import test from "node:test";

import type { ServerConfig } from "../src/config.js";
import { NdsError } from "../src/services/nds/errors.js";
import type { ValidatedGhidraInstallation } from "../src/services/nds/ghidra-installation.js";
import {
  listNdsGhidraCalls,
  listNdsGhidraReferences,
  searchNdsGhidraSymbols,
  type GhidraInspectionDependencies,
} from "../src/services/nds/ghidra-inspection.js";
import type { TrustedGhidraInspectionState } from "../src/services/nds/ghidra-inspection-readiness.js";
import type { NdsOverlay } from "../src/services/nds/overlays.js";
import { readNdsRomMap, type NdsRomMap } from "../src/services/nds/rom-map.js";
import type { RunResult } from "../src/services/process-runner.js";
import { createNdsFixture } from "./helpers/nds-fixture.js";

const SUCCESS_RUN: RunResult = {
  exitCode: 0,
  signal: null,
  stdout: "",
  stderr: "",
  timedOut: false,
  outputTruncated: false,
  outputLimitExceeded: false,
};

const installation: ValidatedGhidraInstallation = {
  home: "/opt/ghidra_12.1.2_PUBLIC",
  analyzeHeadless: "/opt/ghidra_12.1.2_PUBLIC/support/analyzeHeadless",
  version: "12.1.2",
};

function config(workspaceRoot: string): ServerConfig {
  return {
    workspaceRoot,
    commandTimeoutMs: 30_000,
    maxOutputBytes: 256 * 1024,
    ghidraHome: installation.home,
    ghidraTimeoutMs: 900_000,
  };
}

function overlay(overlayId: number): NdsOverlay {
  const ramAddress = 0x02001000;
  const ramSize = 0x20;
  return {
    processor: "arm9",
    overlayId,
    ramAddress,
    ramSize,
    ramEnd: ramAddress + ramSize,
    bssSize: 0x10,
    bssEnd: ramAddress + ramSize + 0x10,
    staticInitStart: 0,
    staticInitEnd: 0,
    fileId: overlayId,
    romOffset: 0x1800 + overlayId * 0x100,
    romSize: ramSize,
    compressedSize: 0,
    flags: 0,
    compressed: false,
  };
}

async function setup(): Promise<{ directory: string; romPath: string; map: NdsRomMap }> {
  const fixture = await createNdsFixture({ fileSize: 0x5000, arm9Size: 0x100, arm7Size: 0x80 });
  const base = await readNdsRomMap(fixture.romPath);
  return {
    directory: fixture.directory,
    romPath: fixture.romPath,
    map: {
      ...base,
      overlays: { arm9: [overlay(7)], arm7: [] },
    },
  };
}

function trusted(map: NdsRomMap, workspaceRoot: string): TrustedGhidraInspectionState {
  return {
    map,
    projectRoot: `${workspaceRoot}/analysis/ghidra/nds/${map.sha256}/project`,
    projectName: `RE-MCP-${map.sha256}`,
    bridgeRoot: `${workspaceRoot}/analysis/generated/nds/${map.sha256Prefix}/ghidra-bridge`,
    bridgeManifestPath: `${workspaceRoot}/analysis/generated/nds/${map.sha256Prefix}/ghidra-bridge/manifest.json`,
    manifestSha256: "f".repeat(64),
    ghidraVersion: "12.1.2",
    completedProcessors: ["arm9", "arm7"],
  };
}

function envelope(request: Record<string, unknown>, payload: unknown) {
  return {
    format: "re-mcp-nds-ghidra-inspection",
    formatVersion: 1,
    requestId: request.requestId,
    sourceRomSha256: request.sourceRomSha256,
    processor: request.processor,
    programName: request.programName,
    operation: request.operation,
    payload,
  };
}

function deps(
  state: TrustedGhidraInspectionState,
  payloadFactory: (request: Record<string, unknown>) => unknown,
): GhidraInspectionDependencies {
  return {
    readTrustedState: async () => state,
    validateInstallation: async () => installation,
    randomBytes: () => Buffer.from("0123456789abcdef", "hex"),
    runInvocation: async (invocation) => {
      const requestPath = invocation.args.at(-2) as string;
      const resultPath = invocation.args.at(-1) as string;
      const request = JSON.parse(await readFile(requestPath, "utf8")) as Record<string, unknown>;
      await mkdir(new URL(".", `file://${resultPath}`).pathname, { recursive: true }).catch(() => undefined);
      await writeFile(resultPath, `${JSON.stringify(envelope(request, payloadFactory(request)))}\n`, "utf8");
      return SUCCESS_RUN;
    },
  };
}

function address(space: string, offset: number, overlaySpace: boolean, defaultSpace: boolean) {
  return { space, offset, overlaySpace, defaultSpace };
}

function evidence(overlayId: string | null = null) {
  return {
    functionId: null,
    functionProof: null,
    functionMode: null,
    overlayId,
  };
}

function isInvalidResult(error: unknown) {
  return error instanceof NdsError && String(error.category) === "ghidra-inspection-result-invalid";
}

test("symbol search validates each item and separates RE-MCP evidence from Ghidra-derived symbol fields", async () => {
  const current = await setup();
  try {
    const state = trusted(current.map, current.directory);
    const result = await searchNdsGhidraSymbols(
      current.romPath,
      { processor: "arm9", query: "FUN_", match: "prefix", limit: 10, offset: 0 },
      config(current.directory),
      deps(state, () => ({
        totalMatches: 1,
        returned: 1,
        offset: 0,
        limit: 10,
        truncated: false,
        results: [{
          name: "FUN_02000000",
          namespace: "Global",
          type: "Function",
          address: address("ram", current.map.header.arm9.ramAddress, false, true),
          primary: true,
          dynamic: false,
          source: "DEFAULT",
          reMcpEvidence: evidence(),
        }],
      })),
    );

    const item = (result.ghidraDerived.results as Array<Record<string, unknown>>)[0]!;
    assert.deepEqual(item.reMcpEvidence, evidence());
    assert.deepEqual(item.ghidraDerived, {
      name: "FUN_02000000",
      namespace: "Global",
      type: "Function",
      address: address("ram", current.map.header.arm9.ramAddress, false, true),
      primary: true,
      dynamic: false,
      source: "DEFAULT",
    });
    assert.equal("name" in item, false, "symbol fields should not be flattened beside authority metadata");
  } finally {
    await rm(current.directory, { recursive: true, force: true });
  }
});

test("reference results validate fields and classify only real default/owned overlay address spaces canonically", async () => {
  const current = await setup();
  try {
    const state = trusted(current.map, current.directory);
    const from = address("ram", current.map.header.arm9.ramAddress, false, true);
    const to = address("RE_MCP_ARM9_OVL_7", 0x02001004, true, false);
    const result = await listNdsGhidraReferences(
      current.romPath,
      { processor: "arm9", runtimeAddress: current.map.header.arm9.ramAddress, direction: "from", limit: 10, offset: 0 },
      config(current.directory),
      deps(state, () => ({
        totalMatches: 1,
        returned: 1,
        offset: 0,
        limit: 10,
        truncated: false,
        results: [{ from, to, type: "UNCONDITIONAL_CALL", source: "ANALYSIS", operandIndex: 0, primary: true }],
      })),
    );
    const item = (result.ghidraDerived.results as Array<Record<string, any>>)[0]!;
    assert.equal(item.canonical.from.component, "main");
    assert.equal(item.canonical.from.overlayId, null);
    assert.equal(item.canonical.to.component, "overlay");
    assert.equal(item.canonical.to.overlayId, 7);
    assert.deepEqual(item.ghidraDerived, {
      from, to, type: "UNCONDITIONAL_CALL", source: "ANALYSIS", operandIndex: 0, primary: true,
    });
  } finally {
    await rm(current.directory, { recursive: true, force: true });
  }
});

test("references from unrelated Ghidra spaces never receive fabricated canonical ownership", async () => {
  const current = await setup();
  try {
    const state = trusted(current.map, current.directory);
    const result = await listNdsGhidraReferences(
      current.romPath,
      { processor: "arm9", runtimeAddress: current.map.header.arm9.ramAddress, direction: "from", limit: 10, offset: 0 },
      config(current.directory),
      deps(state, () => ({
        totalMatches: 1, returned: 1, offset: 0, limit: 10, truncated: false,
        results: [{
          from: address("ram", current.map.header.arm9.ramAddress, false, true),
          to: address("EXTERNAL", current.map.header.arm9.ramAddress, false, false),
          type: "DATA", source: "ANALYSIS", operandIndex: 0, primary: true,
        }],
      })),
    );
    const item = (result.ghidraDerived.results as Array<Record<string, any>>)[0]!;
    assert.equal(item.canonical.to, null);
  } finally {
    await rm(current.directory, { recursive: true, force: true });
  }
});

test("call edges validate function identities and keep direct-call evidence separate from Ghidra flow typing", async () => {
  const current = await setup();
  try {
    const state = trusted(current.map, current.directory);
    const from = address("ram", current.map.header.arm9.ramAddress, false, true);
    const to = address("ram", current.map.header.arm9.ramAddress + 8, false, true);
    const functionIdentity = { entry: from, name: "entry", namespace: "Global" };
    const targetIdentity = { entry: to, name: "callee", namespace: "Global" };
    const directCallEvidence = "{\"kind\":\"direct-call\"}";
    const result = await listNdsGhidraCalls(
      current.romPath,
      { processor: "arm9", runtimeAddress: current.map.header.arm9.ramAddress, direction: "callees", limit: 10, offset: 0 },
      config(current.directory),
      deps(state, () => ({
        found: true,
        function: functionIdentity,
        totalMatches: 1, returned: 1, offset: 0, limit: 10, truncated: false,
        edges: [{
          from, to, type: "UNCONDITIONAL_CALL", source: "ANALYSIS", operandIndex: 0, primary: true,
          callSite: from,
          sourceFunction: functionIdentity,
          targetFunction: targetIdentity,
          reMcpDirectCallEvidence: directCallEvidence,
        }],
      })),
    );
    const edge = (result.ghidraDerived.edges as Array<Record<string, any>>)[0]!;
    assert.deepEqual(edge.reMcpEvidence, { directCall: directCallEvidence });
    assert.equal(edge.ghidraDerived.type, "UNCONDITIONAL_CALL");
    assert.equal(edge.canonical.from.component, "main");
    assert.equal(edge.canonical.to.component, "main");
  } finally {
    await rm(current.directory, { recursive: true, force: true });
  }
});

test("paged inspection results reject malformed item fields and inconsistent pagination metadata", async () => {
  const current = await setup();
  try {
    const state = trusted(current.map, current.directory);
    await assert.rejects(
      searchNdsGhidraSymbols(
        current.romPath,
        { processor: "arm9", query: "FUN_", limit: 10, offset: 0 },
        config(current.directory),
        deps(state, () => ({
          totalMatches: 1, returned: 1, offset: 0, limit: 10, truncated: false,
          results: [{ name: 123 }],
        })),
      ),
      isInvalidResult,
    );
    await assert.rejects(
      listNdsGhidraReferences(
        current.romPath,
        { processor: "arm9", runtimeAddress: current.map.header.arm9.ramAddress, limit: 10, offset: 0 },
        config(current.directory),
        deps(state, () => ({ totalMatches: 1, returned: 0, offset: 0, limit: 9, truncated: false, results: [] })),
      ),
      isInvalidResult,
    );
  } finally {
    await rm(current.directory, { recursive: true, force: true });
  }
});
