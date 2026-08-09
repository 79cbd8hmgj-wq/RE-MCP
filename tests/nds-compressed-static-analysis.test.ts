import assert from "node:assert/strict";
import test from "node:test";

import { createCapstoneArmBackend } from "../src/services/disassembly/capstone.js";
import { analyzeNdsControlFlow } from "../src/services/nds/control-flow.js";
import { disassembleNdsRange } from "../src/services/nds/disassembly.js";
import { analyzeNdsFunction } from "../src/services/nds/function-analysis.js";
import { discoverNdsFunctions } from "../src/services/nds/function-discovery.js";
import { findNdsXrefs } from "../src/services/nds/xrefs.js";
import {
  COMPRESSED_ARM_CODE_DECODED,
  createCompressedArmCodeFixture,
} from "./helpers/nds-compressed-code-fixture.js";

const CFG_LIMITS = {
  maxBlocks: 32,
  maxInstructions: 128,
  maxBytes: 512,
  maxEdges: 64,
} as const;

const XREF_LIMITS = {
  maxComponents: 4,
  maxBlocks: 32,
  maxInstructions: 128,
  maxBytes: 512,
  maxEdges: 64,
  maxXrefs: 32,
} as const;

const FUNCTION_LIMITS = {
  maxComponents: 4,
  maxFunctions: 16,
  maxCallSites: 32,
  maxTotalBlocks: 64,
  maxTotalInstructions: 256,
  maxTotalBytes: 1024,
  maxTotalEdges: 128,
  perFunctionCfg: CFG_LIMITS,
} as const;

test("compressed overlay disassembly consumes decoded runtime bytes with nullable ROM provenance", async () => {
  const { map, runtimeAddress, overlayId } = await createCompressedArmCodeFixture();
  const backend = await createCapstoneArmBackend();
  try {
    const result = await disassembleNdsRange(
      map,
      { processor: "arm9", runtimeAddress, overlayId, mode: "arm" },
      { maxInstructions: 5, maxBytes: 20 },
      backend,
    );
    assert.ok("instructions" in result);
    if (!("instructions" in result)) return;

    assert.deepEqual(
      result.instructions.map((instruction) => instruction.mnemonic),
      ["bl", "ldr", "b", "mov", "bx"],
    );
    assert.deepEqual(
      result.instructions.map((instruction) => instruction.bytesHex),
      ["060000eb", "34009fe5", "000000ea", "0000a0e1", "1eff2fe1"],
    );
    assert.ok(result.instructions.every((instruction) => instruction.romOffset === null));
    assert.equal(result.source.representation, "derived-overlay");
    assert.equal(result.source.runtimeImageOffset, 0);
    assert.deepEqual(
      Buffer.from(result.instructions.map((instruction) => instruction.bytesHex).join(""), "hex"),
      COMPRESSED_ARM_CODE_DECODED.subarray(0, 20),
    );
  } finally {
    backend.close();
  }
});

test("compressed overlay CFG follows deterministic runtime edges without stored-byte interpretation", async () => {
  const { map, runtimeAddress, overlayId } = await createCompressedArmCodeFixture();
  const backend = await createCapstoneArmBackend();
  try {
    const result = await analyzeNdsControlFlow(
      map,
      { processor: "arm9", runtimeAddress, overlayId, mode: "arm" },
      CFG_LIMITS,
      backend,
    );
    assert.ok("blocks" in result);
    if (!("blocks" in result)) return;

    assert.equal(result.entry.romOffset, null);
    assert.equal(result.entry.representation, "derived-overlay");
    assert.ok(result.blocks.some((block) => block.startAddress === runtimeAddress));
    assert.ok(result.blocks.some((block) => block.startAddress === runtimeAddress + 0x10));
    assert.ok(result.calls.some((call) => call.targetAddress === runtimeAddress + 0x20));
  } finally {
    backend.close();
  }
});

test("compressed overlay xrefs preserve exact direct-call evidence with null physical provenance", async () => {
  const { map, runtimeAddress, overlayId } = await createCompressedArmCodeFixture();
  const backend = await createCapstoneArmBackend();
  try {
    const result = await findNdsXrefs(
      map,
      {
        processor: "arm9",
        target: { targetRuntimeAddress: runtimeAddress + 0x20 },
        scope: { kind: "overlay", overlayIds: [overlayId] },
        seeds: [{ runtimeAddress, overlayId, mode: "arm" }],
      },
      XREF_LIMITS,
      backend,
    );

    const directCall = result.xrefs.find((reference) => reference.kind === "direct-call");
    assert.ok(directCall);
    assert.equal(directCall.source.instructionAddress, runtimeAddress);
    assert.equal(directCall.source.instructionRomOffset, null);
    assert.equal(directCall.source.overlayId, overlayId);
    assert.equal(directCall.target.runtimeAddress, runtimeAddress + 0x20);
    assert.equal(result.coverage[0]?.status, "scanned");
  } finally {
    backend.close();
  }
});

test("compressed overlay function discovery proves only exact direct-call targets", async () => {
  const { map, runtimeAddress, overlayId } = await createCompressedArmCodeFixture();
  const backend = await createCapstoneArmBackend();
  try {
    const result = await discoverNdsFunctions(
      map,
      {
        processor: "arm9",
        scope: { kind: "overlay", overlayIds: [overlayId] },
        seeds: [{ runtimeAddress, overlayId, mode: "arm" }],
      },
      FUNCTION_LIMITS,
      backend,
    );

    assert.deepEqual(
      result.functions.map((fn) => fn.entry.runtimeAddress),
      [runtimeAddress + 0x20],
    );
    const callee = result.functions[0];
    assert.ok(callee);
    assert.equal(callee.entry.romOffset, null);
    assert.equal(callee.evidence[0]?.kind, "direct-call");
    if (callee.evidence[0]?.kind === "direct-call") {
      assert.equal(callee.evidence[0].caller.instructionRomOffset, null);
    }
    assert.ok(!result.functions.some((fn) => fn.entry.runtimeAddress === runtimeAddress + 0x30));
  } finally {
    backend.close();
  }
});

test("focused compressed-overlay function analysis shares exact proof and CFG provenance", async () => {
  const { map, runtimeAddress, overlayId } = await createCompressedArmCodeFixture();
  const backend = await createCapstoneArmBackend();
  try {
    const result = await analyzeNdsFunction(
      map,
      {
        processor: "arm9",
        runtimeAddress: runtimeAddress + 0x20,
        overlayId,
        mode: "arm",
        proofScope: { kind: "overlay", overlayIds: [overlayId] },
        seeds: [{ runtimeAddress, overlayId, mode: "arm" }],
      },
      { proof: XREF_LIMITS, cfg: CFG_LIMITS },
      backend,
    );

    assert.equal(result.proofStatus, "proven");
    assert.equal(result.entry.romOffset, null);
    assert.equal(result.callers.length, 1);
    assert.equal(result.callers[0]?.caller.instructionRomOffset, null);
    assert.ok(result.cfg !== null);
    assert.deepEqual(result.returnSites, [runtimeAddress + 0x20]);
  } finally {
    backend.close();
  }
});
