import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import test from "node:test";

import type {
  ArmDisassemblyBackend,
  ArmMode,
  DecodedArmInstruction,
} from "../src/services/disassembly/backend.js";
import {
  analyzeNdsFunction,
  type AnalyzeFunctionLimits,
} from "../src/services/nds/function-analysis.js";
import {
  discoverNdsFunctions,
  type FunctionDiscoveryLimits,
} from "../src/services/nds/function-discovery.js";
import { NdsError } from "../src/services/nds/errors.js";
import { readNdsRomMap } from "../src/services/nds/rom-map.js";
import { createNdsFixture } from "./helpers/nds-fixture.js";

function returned(address: number): DecodedArmInstruction {
  return {
    address,
    size: 4,
    bytes: [0x1e, 0xff, 0x2f, 0xe1],
    mnemonic: "bx",
    operandsText: "lr",
    operands: [{ kind: "register", name: "lr" }],
    isJump: true,
    isCall: false,
    isReturn: true,
    isConditional: false,
    switchesMode: false,
    pcRelative: null,
  };
}

class MutatingBackend implements ArmDisassemblyBackend {
  private mutated = false;

  constructor(private readonly romPath: string) {}

  decodeOne(
    _bytes: Uint8Array,
    address: number,
    _mode: ArmMode,
  ): DecodedArmInstruction | null {
    if (!this.mutated) {
      this.mutated = true;
      const bytes = readFileSync(this.romPath);
      bytes[bytes.length - 1] = (bytes[bytes.length - 1]! ^ 0xff) & 0xff;
      writeFileSync(this.romPath, bytes);
    }
    return returned(address);
  }

  close(): void {}
}

const DISCOVERY_LIMITS: FunctionDiscoveryLimits = {
  maxComponents: 32,
  maxFunctions: 128,
  maxCallSites: 512,
  maxTotalBlocks: 512,
  maxTotalInstructions: 4096,
  maxTotalBytes: 32768,
  maxTotalEdges: 2048,
  perFunctionCfg: {
    maxBlocks: 64,
    maxInstructions: 512,
    maxBytes: 2048,
    maxEdges: 128,
  },
};

const ANALYSIS_LIMITS: AnalyzeFunctionLimits = {
  proof: {
    maxComponents: 32,
    maxBlocks: 128,
    maxInstructions: 2048,
    maxBytes: 8192,
    maxEdges: 512,
    maxXrefs: 256,
  },
  cfg: {
    maxBlocks: 64,
    maxInstructions: 512,
    maxBytes: 2048,
    maxEdges: 128,
  },
};

function isInvalidRom(error: unknown): boolean {
  return error instanceof NdsError && error.category === "invalid-rom";
}

test("function discovery rejects a ROM that changes during bounded CFG reads", async () => {
  const fixture = await createNdsFixture({ arm9Size: 0x20 });
  const map = await readNdsRomMap(fixture.romPath);

  await assert.rejects(
    () => discoverNdsFunctions(
      map,
      { processor: "arm9", scope: { kind: "main" }, seeds: [] },
      DISCOVERY_LIMITS,
      new MutatingBackend(fixture.romPath),
    ),
    isInvalidRom,
  );
});

test("focused function proof rejects a ROM that changes during xref proof reads", async () => {
  const fixture = await createNdsFixture({ arm9Size: 0x20 });
  const map = await readNdsRomMap(fixture.romPath);

  await assert.rejects(
    () => analyzeNdsFunction(
      map,
      {
        processor: "arm9",
        runtimeAddress: 0x02000000,
        mode: "arm",
        proofScope: { kind: "main" },
        seeds: [],
      },
      ANALYSIS_LIMITS,
      new MutatingBackend(fixture.romPath),
    ),
    isInvalidRom,
  );
});
