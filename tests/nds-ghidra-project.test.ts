import assert from "node:assert/strict";
import { access, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

import type { ServerConfig } from "../src/config.js";
import { NdsError } from "../src/services/nds/errors.js";
import type { GeneratedGhidraBridge } from "../src/services/nds/ghidra-bridge.js";
import { buildGhidraBridgeManifest, ghidraProjectName, ghidraProjectRoot, ghidraStateRoot } from "../src/services/nds/ghidra-model.js";
import {
  bootstrapNdsGhidraProject,
  readNdsGhidraStatus,
  type GhidraProjectDependencies,
} from "../src/services/nds/ghidra-project.js";
import type { GhidraInvocation, ValidatedGhidraInstallation } from "../src/services/nds/ghidra-runner.js";
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

async function makeFixture() {
  const fixture = await createNdsFixture({ fileSize: 0x3000, arm9Size: 0x20, arm7Size: 0x20 });
  fixture.buffer.set([0x1e, 0xff, 0x2f, 0xe1], 0x200);
  fixture.buffer.set([0x1e, 0xff, 0x2f, 0xe1], 0x600);
  await fixture.write();
  const map = await readNdsRomMap(fixture.romPath);
  return { fixture, map };
}

async function fakeBridge(map: NdsRomMap, workspaceRoot: string, manifestSha256 = "2".repeat(64)): Promise<GeneratedGhidraBridge> {
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
  return { bridgeRoot, manifestPath, manifestSha256, manifest };
}

function processorFromStage(stage: GhidraInvocation["stage"]): NdsProcessor {
  return stage.startsWith("arm9") ? "arm9" : "arm7";
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
    importedOverlays: processorManifest.overlays.length,
    compressedOverlayIds: processorManifest.overlays
      .filter((entry) => entry.compressed)
      .map((entry) => entry.overlayId),
    provenEntries: discoveryManifest.functions.length,
    directCalls: discoveryManifest.calls.length,
  };
}

async function createProjectMarker(map: NdsRomMap, workspaceRoot: string): Promise<void> {
  const projectRoot = ghidraProjectRoot(map, workspaceRoot);
  await mkdir(projectRoot, { recursive: true });
  await writeFile(path.join(projectRoot, `${ghidraProjectName(map)}.gpr`), "RE-MCP test project\n", "utf8");
  await mkdir(path.join(projectRoot, `${ghidraProjectName(map)}.rep`), { recursive: true });
}

function depsFor(input: {
  map: NdsRomMap;
  workspaceRoot: string;
  bridgeSha?: string;
  failProcessor?: NdsProcessor;
  mutateBeforeRun?: boolean;
  mutateAfterProcessor?: NdsProcessor;
  invocations?: GhidraInvocation[];
}): GhidraProjectDependencies {
  let bridge: GeneratedGhidraBridge | null = null;
  return {
    validateInstallation: async () => INSTALLATION,
    generateBridge: async () => {
      bridge = await fakeBridge(input.map, input.workspaceRoot, input.bridgeSha);
      if (input.mutateBeforeRun) {
        const bytes = await readFile(input.map.romPath);
        bytes[0x200] = (bytes[0x200] ?? 0) ^ 0xff;
        await writeFile(input.map.romPath, bytes);
      }
      return bridge;
    },
    runInvocation: async (invocation) => {
      input.invocations?.push(invocation);
      const processor = processorFromStage(invocation.stage);
      if (input.failProcessor === processor) {
        throw new NdsError("ghidra-analysis-failed", `${processor} synthetic failure`);
      }
      assert.notEqual(bridge, null);
      await createProjectMarker(input.map, input.workspaceRoot);
      const resultPath = path.join(bridge!.bridgeRoot, bridge!.manifest.generatedResultPaths[processor]);
      await writeFile(resultPath, `${JSON.stringify(resultFor(bridge!, processor), null, 2)}\n`, "utf8");
      if (input.mutateAfterProcessor === processor) {
        const bytes = await readFile(input.map.romPath);
        bytes[0x204] = (bytes[0x204] ?? 0) ^ 0xff;
        await writeFile(input.map.romPath, bytes);
      }
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
}

async function readJson(filePath: string): Promise<Record<string, unknown>> {
  return JSON.parse(await readFile(filePath, "utf8")) as Record<string, unknown>;
}

test("Ghidra project bootstrap imports ARM9 then ARM7 and persists validated full-SHA state", async () => {
  const { fixture, map } = await makeFixture();
  const invocations: GhidraInvocation[] = [];
  try {
    const result = await bootstrapNdsGhidraProject(
      fixture.romPath,
      config(fixture.directory),
      depsFor({ map, workspaceRoot: fixture.directory, invocations }),
    );

    assert.equal(result.runKind, "initial");
    assert.deepEqual(invocations.map((entry) => entry.stage), ["arm9-import", "arm7-import"]);
    assert.deepEqual(result.processors.map((entry) => [entry.processor, entry.status]), [
      ["arm9", "imported"],
      ["arm7", "imported"],
    ]);
    assert.equal(result.sourceRomSha256, map.sha256);
    assert.equal(result.ghidraVersion, "12.1.2");

    const stateRoot = ghidraStateRoot(map, fixture.directory);
    const success = await readJson(path.join(stateRoot, "latest-success.json"));
    assert.equal(success.sourceRomSha256, map.sha256);
    assert.equal(success.manifestSha256, "2".repeat(64));
    assert.deepEqual(success.completedProcessors, ["arm9", "arm7"]);
    await access(path.join(ghidraProjectRoot(map, fixture.directory), `${ghidraProjectName(map)}.gpr`));
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
});

test("identical rerun processes both owned programs without overwrite and reports already-current", async () => {
  const { fixture, map } = await makeFixture();
  try {
    await bootstrapNdsGhidraProject(
      fixture.romPath,
      config(fixture.directory),
      depsFor({ map, workspaceRoot: fixture.directory }),
    );
    const invocations: GhidraInvocation[] = [];
    const result = await bootstrapNdsGhidraProject(
      fixture.romPath,
      config(fixture.directory),
      depsFor({ map, workspaceRoot: fixture.directory, invocations }),
    );

    assert.equal(result.runKind, "already-current");
    assert.deepEqual(invocations.map((entry) => entry.stage), ["arm9-process", "arm7-process"]);
    assert.equal(invocations.some((entry) => entry.args.includes("-overwrite")), false);
    assert.equal(invocations.some((entry) => entry.args.includes("-import")), false);
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
});

test("same ROM with a newer bridge manifest reconciles existing programs", async () => {
  const { fixture, map } = await makeFixture();
  try {
    await bootstrapNdsGhidraProject(
      fixture.romPath,
      config(fixture.directory),
      depsFor({ map, workspaceRoot: fixture.directory, bridgeSha: "2".repeat(64) }),
    );
    const invocations: GhidraInvocation[] = [];
    const result = await bootstrapNdsGhidraProject(
      fixture.romPath,
      config(fixture.directory),
      depsFor({ map, workspaceRoot: fixture.directory, bridgeSha: "3".repeat(64), invocations }),
    );
    assert.equal(result.runKind, "reconciled");
    assert.deepEqual(invocations.map((entry) => entry.stage), ["arm9-process", "arm7-process"]);
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
});

test("partial ARM9 success is preserved and retry processes ARM9 while importing missing ARM7", async () => {
  const { fixture, map } = await makeFixture();
  try {
    await assert.rejects(
      bootstrapNdsGhidraProject(
        fixture.romPath,
        config(fixture.directory),
        depsFor({ map, workspaceRoot: fixture.directory, failProcessor: "arm7" }),
      ),
      (error: unknown) => error instanceof NdsError && error.category === "ghidra-analysis-failed",
    );

    const failure = await readJson(path.join(ghidraStateRoot(map, fixture.directory), "latest-failure.json"));
    assert.equal(failure.failedProcessor, "arm7");
    assert.deepEqual(failure.completedProcessors, ["arm9"]);

    const invocations: GhidraInvocation[] = [];
    const retried = await bootstrapNdsGhidraProject(
      fixture.romPath,
      config(fixture.directory),
      depsFor({ map, workspaceRoot: fixture.directory, invocations }),
    );
    assert.equal(retried.runKind, "reconciled");
    assert.deepEqual(invocations.map((entry) => entry.stage), ["arm9-process", "arm7-import"]);
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
});

test("unrecognized existing project fails closed instead of overwriting analyst state", async () => {
  const { fixture, map } = await makeFixture();
  const invocations: GhidraInvocation[] = [];
  try {
    await createProjectMarker(map, fixture.directory);
    await assert.rejects(
      bootstrapNdsGhidraProject(
        fixture.romPath,
        config(fixture.directory),
        depsFor({ map, workspaceRoot: fixture.directory, invocations }),
      ),
      (error: unknown) => error instanceof NdsError && error.category === "project-state-mismatch",
    );
    assert.deepEqual(invocations, []);
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
});

test("stored state for another ROM SHA fails closed", async () => {
  const { fixture, map } = await makeFixture();
  try {
    await createProjectMarker(map, fixture.directory);
    const stateRoot = ghidraStateRoot(map, fixture.directory);
    await mkdir(stateRoot, { recursive: true });
    await writeFile(path.join(stateRoot, "latest-run.json"), `${JSON.stringify({
      format: "re-mcp-nds-ghidra-run-state",
      formatVersion: 1,
      sourceRomSha256: "f".repeat(64),
      manifestSha256: "2".repeat(64),
      completedProcessors: ["arm9"],
    })}\n`, "utf8");

    await assert.rejects(
      bootstrapNdsGhidraProject(
        fixture.romPath,
        config(fixture.directory),
        depsFor({ map, workspaceRoot: fixture.directory }),
      ),
      (error: unknown) => error instanceof NdsError && error.category === "project-state-mismatch",
    );
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
});

test("Ghidra status is non-mutating and does not require a configured Ghidra installation", async () => {
  const { fixture, map } = await makeFixture();
  try {
    const absent = await readNdsGhidraStatus(fixture.romPath, {
      ...config(fixture.directory),
      ghidraHome: null,
    });
    assert.equal(absent.projectExists, false);
    assert.equal(absent.bridgeExists, false);
    assert.equal(absent.sourceRomSha256, map.sha256);

    await bootstrapNdsGhidraProject(
      fixture.romPath,
      config(fixture.directory),
      depsFor({ map, workspaceRoot: fixture.directory }),
    );
    const status = await readNdsGhidraStatus(fixture.romPath, {
      ...config(fixture.directory),
      ghidraHome: "/does/not/exist",
    });
    assert.equal(status.projectExists, true);
    assert.equal(status.bridgeExists, true);
    assert.equal(status.manifestSha256, "2".repeat(64));
    assert.equal(status.ghidraVersion, "12.1.2");
    assert.deepEqual(status.processors.map((entry) => entry.processor), ["arm9", "arm7"]);
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
});

test("ROM mutation before the first Ghidra invocation aborts without launching Ghidra", async () => {
  const { fixture, map } = await makeFixture();
  const invocations: GhidraInvocation[] = [];
  try {
    await assert.rejects(
      bootstrapNdsGhidraProject(
        fixture.romPath,
        config(fixture.directory),
        depsFor({ map, workspaceRoot: fixture.directory, mutateBeforeRun: true, invocations }),
      ),
      (error: unknown) => error instanceof NdsError && error.category === "invalid-rom",
    );
    assert.deepEqual(invocations, []);
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
});

test("ROM mutation after Ghidra execution prevents final success state", async () => {
  const { fixture, map } = await makeFixture();
  try {
    await assert.rejects(
      bootstrapNdsGhidraProject(
        fixture.romPath,
        config(fixture.directory),
        depsFor({ map, workspaceRoot: fixture.directory, mutateAfterProcessor: "arm7" }),
      ),
      (error: unknown) => error instanceof NdsError && error.category === "invalid-rom",
    );
    await assert.rejects(access(path.join(ghidraStateRoot(map, fixture.directory), "latest-success.json")));
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
});