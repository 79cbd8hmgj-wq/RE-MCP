import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

import type { ServerConfig } from "../src/config.js";
import { NdsError, type NdsServiceErrorCategory } from "../src/services/nds/errors.js";
import {
  ghidraGeneratedBridgeRoot,
  ghidraProjectName,
  ghidraProjectRoot,
  ghidraStateRoot,
} from "../src/services/nds/ghidra-model.js";
import { readTrustedGhidraInspectionState } from "../src/services/nds/ghidra-project.js";
import { readNdsRomMap } from "../src/services/nds/rom-map.js";
import { createNdsFixture } from "./helpers/nds-fixture.js";

function config(workspaceRoot: string): ServerConfig {
  return {
    workspaceRoot,
    commandTimeoutMs: 30_000,
    maxOutputBytes: 64 * 1024,
    ghidraHome: "/opt/ghidra_12.1.2_PUBLIC",
    ghidraTimeoutMs: 900_000,
  };
}

function sha256(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

async function setupTrustedState() {
  const fixture = await createNdsFixture({ fileSize: 0x3000, arm9Size: 0x20, arm7Size: 0x20 });
  await fixture.write();
  const map = await readNdsRomMap(fixture.romPath);
  const projectRoot = ghidraProjectRoot(map, fixture.directory);
  const projectName = ghidraProjectName(map);
  await mkdir(projectRoot, { recursive: true });
  await writeFile(path.join(projectRoot, `${projectName}.gpr`), "test project\n", "utf8");
  await mkdir(path.join(projectRoot, `${projectName}.rep`), { recursive: true });

  const bridgeRoot = ghidraGeneratedBridgeRoot(map, fixture.directory);
  await mkdir(bridgeRoot, { recursive: true });
  const manifestText = `${JSON.stringify({
    format: "re-mcp-nds-ghidra",
    formatVersion: 1,
    sourceRomSha256: map.sha256,
  }, null, 2)}\n`;
  const manifestPath = path.join(bridgeRoot, "manifest.json");
  await writeFile(manifestPath, manifestText, "utf8");
  const manifestSha256 = sha256(manifestText);

  const stateRoot = ghidraStateRoot(map, fixture.directory);
  await mkdir(stateRoot, { recursive: true });
  const state = {
    format: "re-mcp-nds-ghidra-run-state",
    formatVersion: 1,
    sourceRomSha256: map.sha256,
    manifestSha256,
    ghidraVersion: "12.1.2",
    stage: "complete",
    existingProcessors: ["arm9", "arm7"],
    completedProcessors: ["arm9", "arm7"],
    processors: [],
  };
  await writeFile(path.join(stateRoot, "latest-run.json"), `${JSON.stringify(state, null, 2)}\n`, "utf8");
  await writeFile(path.join(stateRoot, "latest-success.json"), `${JSON.stringify(state, null, 2)}\n`, "utf8");

  return { fixture, map, projectRoot, bridgeRoot, manifestPath, manifestSha256, stateRoot, state };
}

function isCategory(category: string) {
  return (error: unknown) => error instanceof NdsError && String(error.category) === category;
}

test("inspection error categories are part of the NDS service error union", () => {
  const categories: readonly NdsServiceErrorCategory[] = [
    "ghidra-project-not-current",
    "ghidra-version-mismatch",
    "ghidra-address-not-inspectable",
    "ghidra-inspection-failed",
    "ghidra-inspection-timeout",
    "ghidra-inspection-result-invalid",
  ];
  assert.equal(categories.length, 6);
});

test("trusted Ghidra inspection state requires a complete SHA-scoped project and matching bridge", async () => {
  const setup = await setupTrustedState();
  try {
    const trusted = await readTrustedGhidraInspectionState(
      setup.fixture.romPath,
      config(setup.fixture.directory),
    );
    assert.equal(trusted.map.sha256, setup.map.sha256);
    assert.equal(trusted.projectRoot, setup.projectRoot);
    assert.equal(trusted.bridgeRoot, setup.bridgeRoot);
    assert.equal(trusted.bridgeManifestPath, setup.manifestPath);
    assert.equal(trusted.manifestSha256, setup.manifestSha256);
    assert.equal(trusted.ghidraVersion, "12.1.2");
    assert.deepEqual(trusted.completedProcessors, ["arm9", "arm7"]);
  } finally {
    await rm(setup.fixture.directory, { recursive: true, force: true });
  }
});

test("trusted Ghidra inspection state refuses a missing success sidecar", async () => {
  const setup = await setupTrustedState();
  try {
    await rm(path.join(setup.stateRoot, "latest-success.json"));
    await assert.rejects(
      readTrustedGhidraInspectionState(setup.fixture.romPath, config(setup.fixture.directory)),
      isCategory("ghidra-project-not-current"),
    );
  } finally {
    await rm(setup.fixture.directory, { recursive: true, force: true });
  }
});

test("trusted Ghidra inspection state refuses a later failure sidecar", async () => {
  const setup = await setupTrustedState();
  try {
    await writeFile(path.join(setup.stateRoot, "latest-failure.json"), `${JSON.stringify({
      format: "re-mcp-nds-ghidra-run-state",
      formatVersion: 1,
      sourceRomSha256: setup.map.sha256,
      manifestSha256: setup.manifestSha256,
      ghidraVersion: "12.1.2",
      failedProcessor: "arm7",
      completedProcessors: ["arm9"],
      existingProcessors: ["arm9", "arm7"],
      category: "ghidra-analysis-failed",
      message: "synthetic failure",
    }, null, 2)}\n`, "utf8");
    await assert.rejects(
      readTrustedGhidraInspectionState(setup.fixture.romPath, config(setup.fixture.directory)),
      isCategory("ghidra-project-not-current"),
    );
  } finally {
    await rm(setup.fixture.directory, { recursive: true, force: true });
  }
});

test("trusted Ghidra inspection state refuses an incomplete latest run", async () => {
  const setup = await setupTrustedState();
  try {
    await writeFile(path.join(setup.stateRoot, "latest-run.json"), `${JSON.stringify({
      ...setup.state,
      stage: "arm9-complete",
      completedProcessors: ["arm9"],
    }, null, 2)}\n`, "utf8");
    await assert.rejects(
      readTrustedGhidraInspectionState(setup.fixture.romPath, config(setup.fixture.directory)),
      isCategory("ghidra-project-not-current"),
    );
  } finally {
    await rm(setup.fixture.directory, { recursive: true, force: true });
  }
});

test("trusted Ghidra inspection state refuses a missing or changed bridge manifest", async () => {
  const missing = await setupTrustedState();
  try {
    await rm(missing.manifestPath);
    await assert.rejects(
      readTrustedGhidraInspectionState(missing.fixture.romPath, config(missing.fixture.directory)),
      isCategory("ghidra-project-not-current"),
    );
  } finally {
    await rm(missing.fixture.directory, { recursive: true, force: true });
  }

  const changed = await setupTrustedState();
  try {
    await writeFile(changed.manifestPath, "changed\n", "utf8");
    await assert.rejects(
      readTrustedGhidraInspectionState(changed.fixture.romPath, config(changed.fixture.directory)),
      isCategory("ghidra-project-not-current"),
    );
  } finally {
    await rm(changed.fixture.directory, { recursive: true, force: true });
  }
});
