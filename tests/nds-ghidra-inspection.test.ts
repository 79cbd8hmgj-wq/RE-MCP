import assert from "node:assert/strict";
import { readFile, readdir, rm, writeFile } from "node:fs/promises";
import test from "node:test";

import type { ServerConfig } from "../src/config.js";
import { NdsError } from "../src/services/nds/errors.js";
import type { ValidatedGhidraInstallation } from "../src/services/nds/ghidra-installation.js";
import {
  decompileNdsGhidraFunction,
  inspectNdsGhidraFunction,
  listNdsGhidraReferences,
  resolveGhidraInspectionSelector,
  type GhidraInspectionDependencies,
} from "../src/services/nds/ghidra-inspection.js";
import { ghidraInspectionRoot } from "../src/services/nds/ghidra-inspection-model.js";
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

function config(workspaceRoot: string): ServerConfig {
  return {
    workspaceRoot,
    commandTimeoutMs: 30_000,
    maxOutputBytes: 256 * 1024,
    ghidraHome: "/opt/ghidra_12.1.2_PUBLIC",
    ghidraTimeoutMs: 900_000,
  };
}

function overlay(input: {
  overlayId: number;
  ramAddress: number;
  ramSize?: number;
  bssSize?: number;
  romOffset?: number;
  romSize?: number;
  compressed?: boolean;
}): NdsOverlay {
  const ramSize = input.ramSize ?? 0x20;
  const bssSize = input.bssSize ?? 0;
  const ramEnd = input.ramAddress + ramSize;
  return {
    processor: "arm9",
    overlayId: input.overlayId,
    ramAddress: input.ramAddress,
    ramSize,
    ramEnd,
    bssSize,
    bssEnd: ramEnd + bssSize,
    staticInitStart: 0,
    staticInitEnd: 0,
    fileId: input.overlayId,
    romOffset: input.romOffset ?? 0x1000 + input.overlayId * 0x100,
    romSize: input.romSize ?? ramSize,
    compressedSize: input.compressed ? (input.romSize ?? ramSize) : 0,
    flags: input.compressed ? 1 : 0,
    compressed: input.compressed ?? false,
  };
}

async function inspectionMap(): Promise<{ directory: string; romPath: string; map: NdsRomMap }> {
  const fixture = await createNdsFixture({ fileSize: 0x5000, arm9Size: 0x100, arm7Size: 0x80 });
  const base = await readNdsRomMap(fixture.romPath);
  return {
    directory: fixture.directory,
    romPath: fixture.romPath,
    map: {
      ...base,
      overlays: {
        arm9: [
          overlay({ overlayId: 1, ramAddress: 0x02001000 }),
          overlay({ overlayId: 2, ramAddress: 0x02001000 }),
          overlay({ overlayId: 3, ramAddress: 0x02002000, compressed: true }),
          overlay({ overlayId: 4, ramAddress: 0x02003000, ramSize: 0x10, bssSize: 0x20 }),
        ],
        arm7: [],
      },
    },
  };
}

function errorCategory(category: string) {
  return (error: unknown) => error instanceof NdsError && String(error.category) === category;
}

test("Ghidra inspection selector resolves main through default space and explicit overlapping overlays", async () => {
  const setup = await inspectionMap();
  try {
    const main = resolveGhidraInspectionSelector(
      setup.map,
      { processor: "arm9", runtimeAddress: setup.map.header.arm9.ramAddress },
      "inspect-function",
    );
    assert.equal(main.component, "main");
    assert.equal(main.addressSpace, null);
    assert.equal(main.overlayId, null);
    assert.equal(main.fileBacked, true);

    assert.throws(
      () => resolveGhidraInspectionSelector(
        setup.map,
        { processor: "arm9", runtimeAddress: 0x02001004 },
        "inspect-function",
      ),
      errorCategory("ghidra-address-not-inspectable"),
    );

    const selected = resolveGhidraInspectionSelector(
      setup.map,
      { processor: "arm9", runtimeAddress: 0x02001004, overlayId: 2 },
      "inspect-function",
    );
    assert.equal(selected.component, "overlay");
    assert.equal(selected.overlayId, 2);
    assert.equal(selected.addressSpace, "RE_MCP_ARM9_OVL_2");
  } finally {
    await rm(setup.directory, { recursive: true, force: true });
  }
});

test("Ghidra inspection selector refuses compressed code and limits BSS to address-level references", async () => {
  const setup = await inspectionMap();
  try {
    assert.throws(
      () => resolveGhidraInspectionSelector(
        setup.map,
        { processor: "arm9", runtimeAddress: 0x02002004, overlayId: 3 },
        "inspect-function",
      ),
      errorCategory("ghidra-address-not-inspectable"),
    );

    const bss = resolveGhidraInspectionSelector(
      setup.map,
      { processor: "arm9", runtimeAddress: 0x02003018, overlayId: 4 },
      "list-references",
    );
    assert.equal(bss.bss, true);
    assert.equal(bss.fileBacked, false);

    for (const operation of ["inspect-function", "decompile-function", "list-calls"] as const) {
      assert.throws(
        () => resolveGhidraInspectionSelector(
          setup.map,
          { processor: "arm9", runtimeAddress: 0x02003018, overlayId: 4 },
          operation,
        ),
        errorCategory("ghidra-address-not-inspectable"),
      );
    }
  } finally {
    await rm(setup.directory, { recursive: true, force: true });
  }
});

function trustedState(map: NdsRomMap, workspaceRoot: string): TrustedGhidraInspectionState {
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

const installation: ValidatedGhidraInstallation = {
  home: "/opt/ghidra_12.1.2_PUBLIC",
  analyzeHeadless: "/opt/ghidra_12.1.2_PUBLIC/support/analyzeHeadless",
  version: "12.1.2",
};

function resultEnvelope(request: Record<string, unknown>, payload: unknown) {
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

function dependencies(
  state: TrustedGhidraInspectionState,
  overrides: Partial<GhidraInspectionDependencies> = {},
): GhidraInspectionDependencies {
  return {
    readTrustedState: async () => state,
    validateInstallation: async () => installation,
    randomBytes: () => Buffer.from("0123456789abcdef", "hex"),
    runInvocation: async (invocation) => {
      const requestPath = invocation.args.at(-2);
      const resultPath = invocation.args.at(-1);
      assert.equal(typeof requestPath, "string");
      assert.equal(typeof resultPath, "string");
      const request = JSON.parse(await readFile(requestPath as string, "utf8")) as Record<string, unknown>;
      await writeFile(resultPath as string, `${JSON.stringify(resultEnvelope(request, {
        found: true,
        entry: { space: "ram", offset: 0x02000000 },
        name: "FUN_02000000",
        namespace: "Global",
        signature: "undefined FUN_02000000(void)",
        callingConvention: "unknown",
        thunk: false,
        external: false,
        varArgs: false,
        bodyRanges: [],
        bodyRangesTruncated: false,
        entrySymbol: null,
        reMcpEvidence: { functionId: null, functionProof: null, functionMode: null, overlayId: null },
      }))}\n`, "utf8");
      return SUCCESS_RUN;
    },
    ...overrides,
  };
}

test("Ghidra inspection refuses a configured version different from the trusted project without invoking Ghidra", async () => {
  const setup = await inspectionMap();
  try {
    let invoked = false;
    const state = trustedState(setup.map, setup.directory);
    const deps = dependencies(state, {
      validateInstallation: async () => ({ ...installation, version: "12.1.3" }),
      runInvocation: async () => {
        invoked = true;
        return SUCCESS_RUN;
      },
    });
    await assert.rejects(
      inspectNdsGhidraFunction(
        setup.romPath,
        { processor: "arm9", runtimeAddress: setup.map.header.arm9.ramAddress },
        config(setup.directory),
        deps,
      ),
      errorCategory("ghidra-version-mismatch"),
    );
    assert.equal(invoked, false);
  } finally {
    await rm(setup.directory, { recursive: true, force: true });
  }
});

test("Ghidra function inspection validates result identity, separates authority, and cleans transport files", async () => {
  const setup = await inspectionMap();
  try {
    const state = trustedState(setup.map, setup.directory);
    const result = await inspectNdsGhidraFunction(
      setup.romPath,
      { processor: "arm9", runtimeAddress: setup.map.header.arm9.ramAddress },
      config(setup.directory),
      dependencies(state),
    );
    assert.equal(result.canonical.sourceRomSha256, setup.map.sha256);
    assert.equal(result.canonical.component, "main");
    assert.equal(result.ghidraDerived.found, true);
    assert.equal(result.ghidraDerived.name, "FUN_02000000");
    assert.deepEqual(result.reMcpEvidence, {
      functionId: null,
      functionProof: null,
      functionMode: null,
      overlayId: null,
    });

    const transportRoot = ghidraInspectionRoot(setup.map, setup.directory);
    assert.deepEqual(await readdir(transportRoot), []);
  } finally {
    await rm(setup.directory, { recursive: true, force: true });
  }
});

test("Ghidra inspection rejects mismatched result envelopes and still cleans transport files", async () => {
  const setup = await inspectionMap();
  try {
    const state = trustedState(setup.map, setup.directory);
    const deps = dependencies(state, {
      runInvocation: async (invocation) => {
        const requestPath = invocation.args.at(-2) as string;
        const resultPath = invocation.args.at(-1) as string;
        const request = JSON.parse(await readFile(requestPath, "utf8")) as Record<string, unknown>;
        await writeFile(resultPath, `${JSON.stringify({
          ...resultEnvelope(request, { found: false }),
          requestId: "ffffffffffffffff",
        })}\n`, "utf8");
        return SUCCESS_RUN;
      },
    });
    await assert.rejects(
      inspectNdsGhidraFunction(
        setup.romPath,
        { processor: "arm9", runtimeAddress: setup.map.header.arm9.ramAddress },
        config(setup.directory),
        deps,
      ),
      errorCategory("ghidra-inspection-result-invalid"),
    );
    assert.deepEqual(await readdir(ghidraInspectionRoot(setup.map, setup.directory)), []);
  } finally {
    await rm(setup.directory, { recursive: true, force: true });
  }
});

test("Ghidra inspection rechecks source ROM identity after Ghidra returns", async () => {
  const setup = await inspectionMap();
  try {
    const state = trustedState(setup.map, setup.directory);
    const base = dependencies(state);
    const deps = dependencies(state, {
      runInvocation: async (invocation, serverConfig) => {
        const result = await base.runInvocation(invocation, serverConfig);
        await writeFile(setup.romPath, Buffer.alloc(0x5000, 0x5a));
        return result;
      },
    });
    await assert.rejects(
      inspectNdsGhidraFunction(
        setup.romPath,
        { processor: "arm9", runtimeAddress: setup.map.header.arm9.ramAddress },
        config(setup.directory),
        deps,
      ),
      errorCategory("invalid-rom"),
    );
  } finally {
    await rm(setup.directory, { recursive: true, force: true });
  }
});

test("Ghidra decompile and reference operations validate their operation-specific bounds before invocation", async () => {
  const setup = await inspectionMap();
  try {
    const state = trustedState(setup.map, setup.directory);
    let invoked = false;
    const deps = dependencies(state, {
      runInvocation: async () => {
        invoked = true;
        return SUCCESS_RUN;
      },
    });
    await assert.rejects(
      decompileNdsGhidraFunction(
        setup.romPath,
        { processor: "arm9", runtimeAddress: setup.map.header.arm9.ramAddress, maxCharacters: 100001 },
        config(setup.directory),
        deps,
      ),
      /maxCharacters/i,
    );
    await assert.rejects(
      listNdsGhidraReferences(
        setup.romPath,
        { processor: "arm9", runtimeAddress: setup.map.header.arm9.ramAddress, limit: 1001 },
        config(setup.directory),
        deps,
      ),
      /limit/i,
    );
    assert.equal(invoked, false);
  } finally {
    await rm(setup.directory, { recursive: true, force: true });
  }
});
