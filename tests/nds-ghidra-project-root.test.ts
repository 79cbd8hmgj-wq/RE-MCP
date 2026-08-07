import assert from "node:assert/strict";
import { mkdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

import type { ServerConfig } from "../src/config.js";
import type { GeneratedGhidraBridge } from "../src/services/nds/ghidra-bridge.js";
import {
  buildGhidraBridgeManifest,
  ghidraProjectName,
  ghidraProjectRoot,
} from "../src/services/nds/ghidra-model.js";
import {
  bootstrapNdsGhidraProject,
  type GhidraProjectDependencies,
} from "../src/services/nds/ghidra-project.js";
import type { ValidatedGhidraInstallation } from "../src/services/nds/ghidra-runner.js";
import type { NdsProcessor } from "../src/services/nds/overlays.js";
import { readNdsRomMap, type NdsRomMap } from "../src/services/nds/rom-map.js";
import { createNdsFixture } from "./helpers/nds-fixture.js";

const INSTALLATION: ValidatedGhidraInstallation = {
  home: "/opt/ghidra_12.1.2_PUBLIC",
  analyzeHeadless: "/opt/ghidra_12.1.2_PUBLIC/support/analyzeHeadless",
  version: "12.1.2",
};

function config(workspaceRoot: string): ServerConfig {
  return {
    workspaceRoot,
    commandTimeoutMs: 30_000,
    maxOutputBytes: 64 * 1024,
    ghidraHome: INSTALLATION.home,
    ghidraTimeoutMs: 900_000,
  };
}

function discovery(processor: NdsProcessor) {
  return {
    status: "complete" as const,
    processor,
    functions: [],
    calls: [],
    coverage: [{ component: "main" as const, overlayId: null, status: "scanned" as const }],
    truncationReasons: [],
    totals: {
      functions: 0,
      callSites: 0,
      blocks: 0,
      instructions: 0,
      decodedBytes: 0,
      traversalEdges: 0,
    },
  };
}

async function bridgeFor(map: NdsRomMap, workspaceRoot: string): Promise<GeneratedGhidraBridge> {
  const bridgeRoot = path.join(workspaceRoot, "analysis", "generated", "nds", map.sha256Prefix, "ghidra-bridge");
  const manifestPath = path.join(bridgeRoot, "manifest.json");
  const manifest = buildGhidraBridgeManifest({
    map,
    arm9: discovery("arm9"),
    arm7: discovery("arm7"),
    artifacts: [],
  });
  await mkdir(path.join(bridgeRoot, "results"), { recursive: true });
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  return { bridgeRoot, manifestPath, manifestSha256: "2".repeat(64), manifest };
}

function resultFor(bridge: GeneratedGhidraBridge, processor: NdsProcessor) {
  const processorManifest = bridge.manifest.processors.find((entry) => entry.processor === processor)!;
  const discoveryManifest = bridge.manifest.discovery.find((entry) => entry.processor === processor)!;
  return {
    format: "re-mcp-nds-ghidra-processor-result",
    formatVersion: 1,
    sourceRomSha256: bridge.manifest.sourceRomSha256,
    manifestSha256: bridge.manifestSha256,
    processor,
    programName: processorManifest.programName,
    language: processorManifest.language,
    analysisStatus: "complete",
    ghidraVersion: INSTALLATION.version,
    importedOverlays: 0,
    compressedOverlayIds: [],
    provenEntries: discoveryManifest.functions.length,
    directCalls: discoveryManifest.calls.length,
  };
}

test("first bootstrap creates the deterministic Ghidra project parent before analyzeHeadless", async () => {
  const fixture = await createNdsFixture({ fileSize: 0x3000, arm9Size: 0x20, arm7Size: 0x20 });
  fixture.buffer.set([0x1e, 0xff, 0x2f, 0xe1], 0x200);
  fixture.buffer.set([0x1e, 0xff, 0x2f, 0xe1], 0x600);
  await fixture.write();
  const map = await readNdsRomMap(fixture.romPath);
  let bridge: GeneratedGhidraBridge | null = null;
  let invocationCount = 0;

  const dependencies: GhidraProjectDependencies = {
    validateInstallation: async () => INSTALLATION,
    generateBridge: async () => {
      bridge = await bridgeFor(map, fixture.directory);
      return bridge;
    },
    runInvocation: async (invocation) => {
      invocationCount += 1;
      const root = ghidraProjectRoot(map, fixture.directory);
      assert.equal((await stat(root)).isDirectory(), true);
      assert.equal(path.resolve(invocation.args[0]!), root);

      if (invocationCount === 1) {
        await writeFile(path.join(root, `${ghidraProjectName(map)}.gpr`), "RE-MCP test project\n", "utf8");
        await mkdir(path.join(root, `${ghidraProjectName(map)}.rep`), { recursive: true });
      }

      assert.notEqual(bridge, null);
      const processor: NdsProcessor = invocation.stage.startsWith("arm9") ? "arm9" : "arm7";
      const resultPath = path.join(bridge!.bridgeRoot, bridge!.manifest.generatedResultPaths[processor]);
      await writeFile(resultPath, `${JSON.stringify(resultFor(bridge!, processor), null, 2)}\n`, "utf8");
      return {
        exitCode: 0,
        signal: null,
        stdout: "",
        stderr: "",
        timedOut: false,
        outputTruncated: false,
        outputLimitExceeded: false,
      };
    },
  };

  try {
    const result = await bootstrapNdsGhidraProject(
      fixture.romPath,
      config(fixture.directory),
      dependencies,
    );
    assert.equal(result.runKind, "initial");
    assert.equal(invocationCount, 2);
    assert.equal((await readFile(path.join(
      ghidraProjectRoot(map, fixture.directory),
      `${ghidraProjectName(map)}.gpr`,
    ), "utf8")).includes("RE-MCP"), true);
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
});
