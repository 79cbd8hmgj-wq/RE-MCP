import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import type { ServerConfig } from "../src/config.js";
import { NdsError } from "../src/services/nds/errors.js";
import type { GhidraInspectionAuthorityResult } from "../src/services/nds/ghidra-inspection-service.js";
import {
  createRuntimeGhidraEnricher,
  type RuntimeGhidraAdapterDependencies,
} from "../src/services/nds/runtime-correlation-ghidra.js";
import type { RuntimeCandidate } from "../src/services/nds/resolver.js";

function config(): ServerConfig {
  return {
    workspaceRoot: "/workspace",
    commandTimeoutMs: 30_000,
    maxOutputBytes: 256 * 1024,
    ghidraHome: "/opt/ghidra_12.1.2_PUBLIC",
    ghidraTimeoutMs: 900_000,
  };
}

function candidate(overlayId: number | null): RuntimeCandidate {
  return {
    kind: overlayId === null ? "arm9-main" : "overlay",
    processor: "arm9",
    runtimeAddress: overlayId === null ? 0x02000000 : 0x02200000,
    relativeOffset: 0,
    runtimeImageOffset: 0,
    representation: "rom-backed",
    overlayId,
    fileId: overlayId,
    romOffset: overlayId === null ? 0x4000 : 0x8000,
    backingRomOffset: overlayId === null ? 0x4000 : 0x8000,
    backingRomSize: 0x100,
    compressed: false,
  };
}

function authority(found: boolean): GhidraInspectionAuthorityResult {
  return {
    canonical: { sourceRomSha256: "a".repeat(64), processor: "arm9" },
    reMcpEvidence: null,
    ghidraDerived: { found },
  };
}

function dependencies(overrides: Partial<RuntimeGhidraAdapterDependencies> = {}): RuntimeGhidraAdapterDependencies {
  return {
    inspectFunction: async () => authority(true),
    decompileFunction: async () => authority(true),
    ...overrides,
  };
}

test("runtime Ghidra enrichment inspects main without an overlay selector", async () => {
  let selector: Record<string, unknown> | null = null;
  const enrich = createRuntimeGhidraEnricher(config(), dependencies({
    inspectFunction: async (_romPath, input) => {
      selector = { ...input };
      return authority(true);
    },
  }));

  const result = await enrich({
    romPath: "/workspace/game.nds",
    candidate: candidate(null),
    decompileFunction: false,
  });

  assert.equal(result.status, "available");
  assert.deepEqual(selector, { processor: "arm9", runtimeAddress: 0x02000000 });
  if (result.status === "available") assert.equal(result.decompilation, null);
});

test("runtime Ghidra enrichment keeps the exact canonical overlay ID", async () => {
  const selectors: Record<string, unknown>[] = [];
  const enrich = createRuntimeGhidraEnricher(config(), dependencies({
    inspectFunction: async (_romPath, input) => {
      selectors.push({ ...input });
      return authority(true);
    },
    decompileFunction: async (_romPath, input) => {
      selectors.push({ ...input });
      return authority(true);
    },
  }));

  const result = await enrich({
    romPath: "/workspace/game.nds",
    candidate: candidate(7),
    decompileFunction: true,
  });

  assert.equal(result.status, "available");
  assert.deepEqual(selectors, [
    { processor: "arm9", runtimeAddress: 0x02200000, overlayId: 7 },
    { processor: "arm9", runtimeAddress: 0x02200000, overlayId: 7 },
  ]);
  if (result.status === "available") assert.notEqual(result.decompilation, null);
});

test("runtime Ghidra enrichment decompiles only when the exact inspected function exists", async () => {
  let decompileCalls = 0;
  const enrich = createRuntimeGhidraEnricher(config(), dependencies({
    inspectFunction: async () => authority(false),
    decompileFunction: async () => {
      decompileCalls += 1;
      return authority(true);
    },
  }));

  const result = await enrich({
    romPath: "/workspace/game.nds",
    candidate: candidate(null),
    decompileFunction: true,
  });

  assert.equal(result.status, "available");
  assert.equal(decompileCalls, 0);
  if (result.status === "available") assert.equal(result.decompilation, null);
});

test("runtime Ghidra enrichment maps an unready project without failing canonical correlation", async () => {
  const enrich = createRuntimeGhidraEnricher(config(), dependencies({
    inspectFunction: async () => {
      throw new NdsError("ghidra-project-not-current", "No trusted current project exists");
    },
  }));

  const result = await enrich({
    romPath: "/workspace/game.nds",
    candidate: candidate(null),
    decompileFunction: false,
  });

  assert.deepEqual(result, {
    status: "not-ready",
    reason: "No trusted current project exists",
  });
});

test("runtime Ghidra enrichment preserves other Ghidra failure categories", async () => {
  const enrich = createRuntimeGhidraEnricher(config(), dependencies({
    inspectFunction: async () => {
      throw new NdsError("ghidra-inspection-timeout", "Inspection timed out");
    },
  }));

  const result = await enrich({
    romPath: "/workspace/game.nds",
    candidate: candidate(null),
    decompileFunction: false,
  });

  assert.deepEqual(result, {
    status: "failed",
    category: "ghidra-inspection-timeout",
    message: "Inspection timed out",
  });
});

test("runtime Ghidra adapter exposes no bootstrap or reconciliation dependency", async () => {
  const source = await readFile(
    new URL("../src/services/nds/runtime-correlation-ghidra.ts", import.meta.url),
    "utf8",
  );
  assert.doesNotMatch(source, /bootstrap|reconcil/iu);
});
