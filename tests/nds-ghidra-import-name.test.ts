import assert from "node:assert/strict";
import { rm } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

import type { DiscoverNdsFunctionsResult } from "../src/services/nds/function-discovery.js";
import { buildGhidraBridgeManifest } from "../src/services/nds/ghidra-model.js";
import type { NdsProcessor } from "../src/services/nds/overlays.js";
import { readNdsRomMap } from "../src/services/nds/rom-map.js";
import { createNdsFixture } from "./helpers/nds-fixture.js";

function discovery(processor: NdsProcessor): DiscoverNdsFunctionsResult {
  return {
    status: "complete",
    processor,
    functions: [],
    calls: [],
    coverage: [{ component: "main", overlayId: null, status: "scanned" }],
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

test("Ghidra main import artifact basename equals the deterministic project program name", async () => {
  const fixture = await createNdsFixture({ arm9Size: 0x20, arm7Size: 0x20 });
  try {
    const map = await readNdsRomMap(fixture.romPath);
    const manifest = buildGhidraBridgeManifest({
      map,
      arm9: discovery("arm9"),
      arm7: discovery("arm7"),
      artifacts: [],
    });

    for (const processor of manifest.processors) {
      assert.equal(path.posix.basename(processor.main.artifactPath), processor.programName);
      assert.equal(processor.main.artifactPath.startsWith("imports/"), true);
    }
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
});
